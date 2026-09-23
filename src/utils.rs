#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppUid(pub i64);

pub fn get_current_time_in_milliseconds() -> i64 {
    let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut current_time) };
    current_time.tv_sec * 1000 + (current_time.tv_nsec / 1_000_000)
}

pub trait ParcelExt {
    fn data(&self) -> &[u8];
}

impl ParcelExt for rsbinder::Parcel {
    fn data(&self) -> &[u8] {
        unsafe {
            let data = self.as_ptr();
            let parcel_size = self.data_size();
            std::slice::from_raw_parts(data, parcel_size)
        }
    }
}
