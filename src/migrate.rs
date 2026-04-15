use rusqlite::{
    Transaction,
    params,
};

#[allow(dead_code)]
pub static VAULT_VERSION_ID: i64 = 1;

#[allow(dead_code)]
pub static VAULT_MIGRATIONS: [(u32, &str); 1] = [
    (1, include_str!("../data/migrations/0001-initial.sql")),
];

#[derive(Debug)]
pub enum MigrationError {
    InitializationFailed(rusqlite::Error),
    MigrationFailed(u32, rusqlite::Error),
    FinalizationFailed(rusqlite::Error),
}

#[allow(dead_code)]
fn get_and_clear_migration_version(transaction: &mut Transaction<'_>, id: i64) -> Result<u32, rusqlite::Error> {
    transaction.execute(r#"
        create table
            if not exists
            mccv_migration_version
        (
            id integer,
            version integer
        )
    "#, [])?;

    let version: u32 = transaction
        .prepare(r#"select version from mccv_migration_version where id = ?"#)?
        .query_map(params![id], |row| row.get(0))?
        .next()
        .unwrap_or(Ok(0))?;

    transaction.execute(r#"delete from mccv_migration_version where id = ?"#, params![id])?;

    Ok(version)
}

#[allow(dead_code)]
pub fn migrate(transaction: &mut Transaction<'_>, id: i64, migrations: &[(u32, &str)]) -> Result<(u32, u32), MigrationError> {
    let mut version = get_and_clear_migration_version(transaction, id)
        .map_err(|e| MigrationError::InitializationFailed(e))?;

    let initial_version = version;

    for (migration_version, script) in migrations.iter() {
        let migration_version = *migration_version;
        if migration_version > version {
            transaction.execute_batch(script)
            .map_err(|e| MigrationError::MigrationFailed(migration_version, e))?;
            version = migration_version;
        }
    }

    transaction.execute(r#"insert into mccv_migration_version (version, id) values (?, ?)"#, params![version, id])
        .map_err(MigrationError::FinalizationFailed)?;

    Ok((initial_version, version))
}
