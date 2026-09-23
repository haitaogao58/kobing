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

use super::*;
use crate::keymaster::error::tests;
use anyhow::Result;
use rusqlite::types::ToSql;
use rusqlite::{params, Connection};

#[test]
fn test_new_from_sql_enum_i32() -> Result<()> {
    let db = init_db()?;
    insert_into_keyparameter(
        &db,
        1,
        Tag::ALGORITHM.0,
        &Algorithm::RSA.0,
        SecurityLevel::STRONGBOX.0,
    )?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(Tag::ALGORITHM, key_param.get_tag());
    assert_eq!(
        *key_param.key_parameter_value(),
        KeyParameterValue::Algorithm(Algorithm::RSA)
    );
    assert_eq!(*key_param.security_level(), SecurityLevel::STRONGBOX);
    Ok(())
}

#[test]
fn test_new_from_sql_i32() -> Result<()> {
    let db = init_db()?;
    insert_into_keyparameter(&db, 1, Tag::KEY_SIZE.0, &1024, SecurityLevel::STRONGBOX.0)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(Tag::KEY_SIZE, key_param.get_tag());
    assert_eq!(
        *key_param.key_parameter_value(),
        KeyParameterValue::KeySize(1024)
    );
    Ok(())
}

#[test]
fn test_new_from_sql_i64() -> Result<()> {
    let db = init_db()?;

    insert_into_keyparameter(
        &db,
        1,
        Tag::RSA_PUBLIC_EXPONENT.0,
        &(i64::MAX),
        SecurityLevel::STRONGBOX.0,
    )?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(Tag::RSA_PUBLIC_EXPONENT, key_param.get_tag());
    assert_eq!(
        *key_param.key_parameter_value(),
        KeyParameterValue::RSAPublicExponent(i64::MAX)
    );
    Ok(())
}

#[test]
fn test_new_from_sql_bool() -> Result<()> {
    let db = init_db()?;
    insert_into_keyparameter(
        &db,
        1,
        Tag::CALLER_NONCE.0,
        &Null,
        SecurityLevel::STRONGBOX.0,
    )?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(Tag::CALLER_NONCE, key_param.get_tag());
    assert_eq!(
        *key_param.key_parameter_value(),
        KeyParameterValue::CallerNonce
    );
    Ok(())
}

#[test]
fn test_new_from_sql_vec_u8() -> Result<()> {
    let db = init_db()?;
    let app_id = String::from("MyAppID");
    let app_id_bytes = app_id.into_bytes();
    insert_into_keyparameter(
        &db,
        1,
        Tag::APPLICATION_ID.0,
        &app_id_bytes,
        SecurityLevel::STRONGBOX.0,
    )?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(Tag::APPLICATION_ID, key_param.get_tag());
    assert_eq!(
        *key_param.key_parameter_value(),
        KeyParameterValue::ApplicationID(app_id_bytes)
    );
    Ok(())
}

#[test]
fn test_to_sql_enum_i32() -> Result<()> {
    let db = init_db()?;
    let kp = KeyParameter::new(
        KeyParameterValue::Algorithm(Algorithm::RSA),
        SecurityLevel::STRONGBOX,
    );
    store_keyparameter(&db, 1, &kp)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(kp.get_tag(), key_param.get_tag());
    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
    assert_eq!(kp.security_level(), key_param.security_level());
    Ok(())
}

#[test]
fn test_to_sql_i32() -> Result<()> {
    let db = init_db()?;
    let kp = KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::STRONGBOX);
    store_keyparameter(&db, 1, &kp)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(kp.get_tag(), key_param.get_tag());
    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
    assert_eq!(kp.security_level(), key_param.security_level());
    Ok(())
}

#[test]
fn test_to_sql_i64() -> Result<()> {
    let db = init_db()?;

    let kp = KeyParameter::new(
        KeyParameterValue::RSAPublicExponent(i64::MAX),
        SecurityLevel::STRONGBOX,
    );
    store_keyparameter(&db, 1, &kp)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(kp.get_tag(), key_param.get_tag());
    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
    assert_eq!(kp.security_level(), key_param.security_level());
    Ok(())
}

#[test]
fn test_to_sql_vec_u8() -> Result<()> {
    let db = init_db()?;
    let kp = KeyParameter::new(
        KeyParameterValue::ApplicationID(String::from("MyAppID").into_bytes()),
        SecurityLevel::STRONGBOX,
    );
    store_keyparameter(&db, 1, &kp)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(kp.get_tag(), key_param.get_tag());
    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
    assert_eq!(kp.security_level(), key_param.security_level());
    Ok(())
}

#[test]
fn test_to_sql_bool() -> Result<()> {
    let db = init_db()?;
    let kp = KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::STRONGBOX);
    store_keyparameter(&db, 1, &kp)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(kp.get_tag(), key_param.get_tag());
    assert_eq!(kp.key_parameter_value(), key_param.key_parameter_value());
    assert_eq!(kp.security_level(), key_param.security_level());
    Ok(())
}

#[test]
fn test_invalid_tag() -> Result<()> {
    let db = init_db()?;
    insert_into_keyparameter(&db, 1, 0, &123, 1)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(Tag::INVALID, key_param.get_tag());
    Ok(())
}

#[test]
fn test_non_existing_enum_variant() -> Result<()> {
    let db = init_db()?;
    insert_into_keyparameter(&db, 1, 100, &123, 1)?;
    let key_param = query_from_keyparameter(&db)?;
    assert_eq!(Tag::INVALID, key_param.get_tag());
    Ok(())
}

#[test]
fn test_invalid_conversion_from_sql() -> Result<()> {
    let db = init_db()?;
    insert_into_keyparameter(&db, 1, Tag::ALGORITHM.0, &Null, 1)?;
    tests::check_result_contains_error_string(
        query_from_keyparameter(&db),
        "Failed to read sql data for tag: ALGORITHM.",
    );
    Ok(())
}

fn init_db() -> Result<Connection> {
    let db = Connection::open_in_memory().context("Failed to initialize sqlite connection.")?;
    db.execute("ATTACH DATABASE ? as 'persistent';", params![""])
        .context("Failed to attach databases.")?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
                                keyentryid INTEGER,
                                tag INTEGER,
                                data ANY,
                                security_level INTEGER);",
        [],
    )
    .context("Failed to initialize \"keyparameter\" table.")?;
    Ok(db)
}

fn insert_into_keyparameter<T: ToSql>(
    db: &Connection,
    key_id: i64,
    tag: i32,
    value: &T,
    security_level: i32,
) -> Result<()> {
    db.execute(
        "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                VALUES(?, ?, ?, ?);",
        params![key_id, tag, *value, security_level],
    )?;
    Ok(())
}

fn store_keyparameter(db: &Connection, key_id: i64, kp: &KeyParameter) -> Result<()> {
    db.execute(
        "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                VALUES(?, ?, ?, ?);",
        params![
            key_id,
            kp.get_tag().0,
            kp.key_parameter_value(),
            kp.security_level().0
        ],
    )?;
    Ok(())
}

fn query_from_keyparameter(db: &Connection) -> Result<KeyParameter> {
    let mut stmt = db.prepare("SELECT tag, data, security_level FROM persistent.keyparameter")?;
    let mut rows = stmt.query([])?;
    let row = rows.next()?.unwrap();
    KeyParameter::new_from_sql(
        Tag(row.get(0)?),
        &SqlField::new(1, row),
        SecurityLevel(row.get(2)?),
    )
}
