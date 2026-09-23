// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{any::Any, any::TypeId, time::Duration};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    sync::{Condvar, Mutex, MutexGuard},
    thread,
};

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq)]
enum State {
    Exiting,
    Running,
}

#[derive(Debug, Default)]
pub struct Shelf(HashMap<TypeId, Box<dyn Any + Send>>);

impl Shelf {
    pub fn get_downcast_ref<T: Any + Send>(&self) -> Option<&T> {
        self.0
            .get(&TypeId::of::<T>())
            .and_then(|v| v.downcast_ref::<T>())
    }

    pub fn get_downcast_mut<T: Any + Send>(&mut self) -> Option<&mut T> {
        self.0
            .get_mut(&TypeId::of::<T>())
            .and_then(|v| v.downcast_mut::<T>())
    }

    pub fn remove_downcast_ref<T: Any + Send>(&mut self) -> Option<T> {
        self.0
            .remove(&TypeId::of::<T>())
            .and_then(|v| v.downcast::<T>().ok().map(|b| *b))
    }

    pub fn put<T: Any + Send>(&mut self, v: T) -> Option<T> {
        self.0
            .insert(TypeId::of::<T>(), Box::new(v) as Box<dyn Any + Send>)
            .and_then(|v| v.downcast::<T>().ok().map(|b| *b))
    }

    pub fn get_mut<T: Any + Send + Default>(&mut self) -> &mut T {
        self.0
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::<T>::default() as Box<dyn Any + Send>)
            .downcast_mut::<T>()
            .unwrap()
    }

    pub fn get_or_put_with<T: Any + Send, F>(&mut self, init: F) -> &mut T
    where
        F: FnOnce() -> T,
    {
        self.0
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(init()) as Box<dyn Any + Send>)
            .downcast_mut::<T>()
            .unwrap()
    }
}

type QueuedFn = Box<dyn FnOnce(&mut Shelf) + Send>;
type IdleFn = Arc<dyn Fn(&mut Shelf) + Send + Sync>;

struct AsyncTaskState {
    state: State,
    thread: Option<thread::JoinHandle<()>>,
    timeout: Duration,
    hi_prio_req: VecDeque<QueuedFn>,
    lo_prio_req: VecDeque<QueuedFn>,
    idle_fns: Vec<IdleFn>,

    shelf: Option<Shelf>,
}

pub struct AsyncTask {
    state: Arc<(Condvar, Mutex<AsyncTaskState>)>,
}

impl Default for AsyncTask {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

impl AsyncTask {
    pub fn new(timeout: Duration) -> Self {
        Self {
            state: Arc::new((
                Condvar::new(),
                Mutex::new(AsyncTaskState {
                    state: State::Exiting,
                    thread: None,
                    timeout,
                    hi_prio_req: VecDeque::new(),
                    lo_prio_req: VecDeque::new(),
                    idle_fns: Vec::new(),
                    shelf: None,
                }),
            )),
        }
    }

    pub fn queue_hi<F>(&self, f: F)
    where
        F: for<'r> FnOnce(&'r mut Shelf) + Send + 'static,
    {
        self.queue(f, true)
    }

    pub fn queue_lo<F>(&self, f: F)
    where
        F: FnOnce(&mut Shelf) + Send + 'static,
    {
        self.queue(f, false)
    }

    pub fn add_idle<F>(&self, f: F)
    where
        F: Fn(&mut Shelf) + Send + Sync + 'static,
    {
        let (ref _condvar, ref state) = *self.state;
        let mut state = state.lock().unwrap();
        state.idle_fns.push(Arc::new(f));
    }

    fn queue<F>(&self, f: F, hi_prio: bool)
    where
        F: for<'r> FnOnce(&'r mut Shelf) + Send + 'static,
    {
        self.queue_if(|_state| true, f, hi_prio);
    }

    fn queue_if<C, F>(&self, condition: C, f: F, hi_prio: bool) -> bool
    where
        C: FnOnce(&AsyncTaskState) -> bool,
        F: for<'r> FnOnce(&'r mut Shelf) + Send + 'static,
    {
        let (ref condvar, ref state) = *self.state;
        let mut state = state.lock().unwrap();

        let add_to_queue = condition(&state);
        if !add_to_queue {
            return false;
        }

        if hi_prio {
            state.hi_prio_req.push_back(Box::new(f));
        } else {
            state.lo_prio_req.push_back(Box::new(f));
        }

        if state.state != State::Running {
            self.spawn_thread(&mut state);
        }
        drop(state);
        condvar.notify_all();
        true
    }

    pub fn queue_hi_if_running<F>(&self, f: F) -> bool
    where
        F: FnOnce(&mut Shelf) + Send + 'static,
    {
        self.queue_if(
            |state| state.state == State::Running || !state.hi_prio_req.is_empty(),
            f,
            true,
        )
    }

    fn spawn_thread(&self, state: &mut MutexGuard<AsyncTaskState>) {
        if let Some(t) = state.thread.take() {
            t.join().expect("AsyncTask panicked.");
        }

        let cloned_state = self.state.clone();
        let timeout_period = state.timeout;

        state.thread = Some(thread::spawn(move || {
            if crate::keymaster::flags::renice_async_task() {
                crate::keymaster::utils::self_renice(0);
            }

            let (ref condvar, ref state) = *cloned_state;

            enum Action {
                QueuedFn(QueuedFn),
                IdleFns(Vec<IdleFn>),
            }
            let mut done_idle = false;

            let mut shelf = state.lock().unwrap().shelf.take().unwrap_or_default();
            loop {
                if let Some(action) = {
                    let state = state.lock().unwrap();
                    if !done_idle && state.hi_prio_req.is_empty() && state.lo_prio_req.is_empty() {
                        Some(Action::IdleFns(state.idle_fns.clone()))
                    } else {
                        let (mut state, timeout) = condvar
                            .wait_timeout_while(state, timeout_period, |state| {
                                state.hi_prio_req.is_empty() && state.lo_prio_req.is_empty()
                            })
                            .unwrap();
                        match (
                            state.hi_prio_req.pop_front(),
                            state.lo_prio_req.is_empty(),
                            timeout.timed_out(),
                        ) {
                            (Some(f), _, _) => Some(Action::QueuedFn(f)),
                            (None, false, _) => {
                                state.lo_prio_req.pop_front().map(|f| Action::QueuedFn(f))
                            }
                            (None, true, true) => {
                                state.shelf = Some(shelf);
                                state.state = State::Exiting;
                                break;
                            }
                            (None, true, false) => None,
                        }
                    }
                } {
                    match action {
                        Action::QueuedFn(f) => {
                            f(&mut shelf);
                            done_idle = false;
                        }
                        Action::IdleFns(idle_fns) => {
                            for idle_fn in idle_fns {
                                idle_fn(&mut shelf);
                            }
                            done_idle = true;
                        }
                    }
                }
            }
        }));
        state.state = State::Running;
    }
}
