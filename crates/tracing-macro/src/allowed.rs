use std::sync::LazyLock;

use fuzzy_search::basic::fuzzy_search;

const ALLOW_LIST: &str = include_str!("../allowlist.txt");

/// Set of permitted OpenTelemetry field names, copied into the binary `allowlist.txt`.
///
/// Lines that are empty or start with `#` are ignored.
///
/// Example:
/// ```text
/// foo.bar.baz
/// baz_anything_goes
/// technically.🪤.works.but.really.you_should_not
/// ```
static ALLOWED_OPENTELEMETRY_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    Vec::from_iter(
        ALLOW_LIST
            .lines()
            .map(str::trim)
            .filter(|trimmed| !trimmed.is_empty() && !trimmed.starts_with('#')),
    )
});

/// Checks `dotted` against the open telemetry field allowlist.
///
/// Succeeds when the given name is present in `allowlist.txt` verbatim,
/// otherwise provides suggestions in increasing levenshtein distance.
pub(crate) fn check(dotted: &str) -> Result<(), Vec<String>> {
    if ALLOWED_OPENTELEMETRY_NAMES.contains(&dotted) {
        return Ok(());
    }

    let owned: Vec<String> = ALLOWED_OPENTELEMETRY_NAMES.iter().map(|s| (*s).to_string()).collect();
    let suggestions = fuzzy_search(dotted, &owned, 5, fuzzy_search::distance::levenshtein);
    Err(suggestions)
}
