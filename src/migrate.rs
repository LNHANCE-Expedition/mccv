use rusqlite::{
    Connection,
    params,
};

pub fn configure(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.pragma_update(None, "foreign_keys", 1)
}

static MIGRATIONS: [(u32, &str); 1] = [
    (1, include_str!("../data/migrations/0001-initial.sql")),
];

#[derive(Debug)]
pub enum MigrationError {
    InitializationFailed(rusqlite::Error),
    MigrationFailed(u32, rusqlite::Error),
    FinalizationFailed(rusqlite::Error),
}

fn get_and_clear_migration_version(connection: &mut Connection) -> Result<(rusqlite::Transaction<'_>, u32), rusqlite::Error> {
    connection.execute(r#"
        create table
            if not exists
            mccv_migration_version
        (
            version integer
        )
    "#, [])?;

    let transaction = connection.transaction()?;

    let version: u32 = transaction
        .prepare(r#"select version from mccv_migration_version"#)?
        .query_map([], |row| row.get(0))?
        .next().unwrap_or(Ok(0))?;

    transaction.execute(r#"delete from mccv_migration_version"#, [])?;

    Ok((transaction, version))
}

pub fn migrate(connection: &mut Connection) -> Result<(u32, u32), MigrationError> {
    let (transaction, mut version) = get_and_clear_migration_version(connection)
        .map_err(|e| MigrationError::InitializationFailed(e))?;

    let initial_version = version;

    for (migration_version, script) in MIGRATIONS.iter() {
        let migration_version = *migration_version;
        if migration_version > version {
            transaction.execute_batch(script)
            .map_err(|e| MigrationError::MigrationFailed(migration_version, e))?;
            version = migration_version;
        }
    }

    transaction.execute(r#"insert into mccv_migration_version (version) values (?)"#, params![version])
        .map_err(|e| MigrationError::FinalizationFailed(e))?;

    transaction.commit()
        .map_err(|e| MigrationError::FinalizationFailed(e))?;

    Ok((initial_version, version))
}
