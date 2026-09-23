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

use crate::keymaster::error::Error as KsError;
use anyhow::{Context, Result};
use rusqlite::{types::FromSql, Row, Rows};

pub fn with_rows_extract_one<'a, T, F>(rows: &mut Rows<'a>, row_extractor: F) -> Result<T>
where
    F: FnOnce(Option<&Row<'a>>) -> Result<T>,
{
    let result = row_extractor(
        rows.next()
            .context("with_rows_extract_one: Failed to unpack row.")?,
    );

    rows.next()
        .context("In with_rows_extract_one: Failed to unpack unexpected row.")?
        .map_or_else(|| Ok(()), |_| Err(KsError::sys()))
        .context("In with_rows_extract_one: Unexpected row.")?;

    result
}

pub fn with_rows_extract_all<'a, F>(rows: &mut Rows<'a>, mut row_extractor: F) -> Result<()>
where
    F: FnMut(&Row<'a>) -> Result<()>,
{
    loop {
        match rows
            .next()
            .context("In with_rows_extract_all: Failed to unpack row")?
        {
            Some(row) => {
                row_extractor(row).context("In with_rows_extract_all.")?;
            }
            None => break Ok(()),
        }
    }
}

pub struct SqlField<'a>(usize, &'a Row<'a>);

impl<'a> SqlField<'a> {
    pub fn new(index: usize, row: &'a Row<'a>) -> Self {
        Self(index, row)
    }

    pub fn get<T: FromSql>(&self) -> rusqlite::Result<T> {
        self.1.get(self.0)
    }
}

#[macro_export]
macro_rules! impl_metadata {


    (@gen_consts {} {$($n:ident $nid:tt,)*} {$($count:tt)*}) => {
        $(


            #[allow(non_upper_case_globals)]
            const $n: i64 = $nid;
        )*
    };
    (@gen_consts {$first:ident $(,$tail:ident)*} {$($out:tt)*} {$($count:tt)*}) => {
        impl_metadata!(@gen_consts {$($tail),*} {$($out)* $first ($($count)*),} {$($count)* + 1});
    };
    (
        $(#[$nmeta:meta])*
        $nvis:vis struct $name:ident;
        $(#[$emeta:meta])*
        $evis:vis enum $entry:ident {
            $($(#[$imeta:meta])* $vname:ident($t:ty) with accessor $func:ident),* $(,)?
        };
    ) => {
        $(#[$emeta])*
        $evis enum $entry {
            $(
                $(#[$imeta])*
                $vname($t),
            )*
        }

        impl $entry {
            fn db_tag(&self) -> i64 {
                match self {
                    $(Self::$vname(_) => $name::$vname,)*
                }
            }

            fn new_from_sql(db_tag: i64, data: &SqlField) -> anyhow::Result<Self> {
                match db_tag {
                    $(
                        $name::$vname => {
                            Ok($entry::$vname(
                                data.get()
                                .with_context(|| format!(
                                    "In {}::new_from_sql: Unable to get {}.",
                                    stringify!($entry),
                                    stringify!($vname)
                                ))?
                            ))
                        },
                    )*
                    _ => Err(anyhow!(format!(
                        "In {}::new_from_sql: unknown db tag {}.",
                        stringify!($entry), db_tag
                    ))),
                }
            }
        }

        impl rusqlite::types::ToSql for $entry {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                match self {
                    $($entry::$vname(v) => v.to_sql(),)*
                }
            }
        }

        $(#[$nmeta])*
        $nvis struct $name {
            data: std::collections::HashMap<i64, $entry>,
        }

        impl $name {

            pub fn new() -> Self {
                Self{data: std::collections::HashMap::new()}
            }

            impl_metadata!{@gen_consts {$($vname),*} {} {0}}


            pub fn add(&mut self, entry: $entry) {
                self.data.insert(entry.db_tag(), entry);
            }
            $(

                pub fn $func(&self) -> Option<&$t> {
                    if let Some($entry::$vname(v)) = self.data.get(&Self::$vname) {
                        Some(v)
                    } else {
                        None
                    }
                }
            )*
        }
    };
}
