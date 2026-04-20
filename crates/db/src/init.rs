use std::sync::Once;

static INIT: Once = Once::new();

/// Initialize SQLite configuration.
///
/// SQLite has a global configuration that must be initialized before any other SQLite operations.
pub(super) fn initialize_sqlite_configuration() {
    INIT.call_once(|| {
        disable_sqlite_memory_accounting();
    });
}

/// Disables the collection of memory allocation statistics.
///
/// Some of our queries through Diesel are not cacheable, causing SQLite re-parsing the actual
/// queries on each and every invocation. This in turn results in a large number of memory
/// allocations performed via SQLite's malloc wrapper.
///
/// Having memory allocation statistics makes SQLite serialize all allocations through a global
/// mutex, which in turn results in significant lock contention.
///
/// According to the [documentation](https://sqlite.org/c3ref/c_config_covering_index_scan.html)
/// the only thing we lose is access to memory allocation statistics -- we don't use that.
fn disable_sqlite_memory_accounting() {
    let result =
        unsafe { libsqlite3_sys::sqlite3_config(libsqlite3_sys::SQLITE_CONFIG_MEMSTATUS, 0) };
    assert!(result == libsqlite3_sys::SQLITE_OK);
}
