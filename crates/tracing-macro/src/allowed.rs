use std::sync::LazyLock;

use fuzzy_search::basic::fuzzy_search;

use crate::instrument::Name;

const ALLOW_LIST: &str = include_str!("../allowlist.txt");

/// Set of permitted otel field names, copied into the binary `allowlist.txt`.
///
/// Lines that are empty or start with `#` are ignored.
///
/// Example:
/// ```
/// foo.bar.baz
/// baz_anything_goes
/// technically.🪤.works.but.really.you_should_not
/// ```
static ALLOWED_OTEL_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    Vec::from_iter(
        ALLOW_LIST
            .lines()
            .map(|line| line.trim())
            .filter(|trimmed| !trimmed.is_empty() && !trimmed.starts_with('#')),
    )
});

/// Checks `name` against the open telemetry field allowlist.
///
/// Succeeds when the given name is present in `allowlist.txt` verbatim,
/// otherwise provides suggestions in increasing levenshtein distance.
pub(crate) fn check(name: &Name) -> Result<(), Vec<String>> {
    let dotted = name.to_dotted_string();
    if ALLOWED_OTEL_NAMES.contains(&dotted.as_str()) {
        return Ok(());
    }

    let owned: Vec<String> = ALLOWED_OTEL_NAMES.iter().map(|s| s.to_string()).collect();
    let suggestions = fuzzy_search(&dotted, &owned, 5, fuzzy_search::distance::levenshtein);
    Err(suggestions)
}
