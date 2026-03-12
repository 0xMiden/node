use std::sync::LazyLock;

use fuzzy_search::basic::fuzzy_search;

use crate::instrument::Name;

const ALLOW_LIST: &str = include_str!("../allowlist.txt");

static ALLOWED_OTEL_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    Vec::from_iter(
        ALLOW_LIST
            .lines()
            .map(|line| line.trim())
            .filter(|trimmed| !trimmed.starts_with('#')),
    )
});

struct Suggestions {
    orig: Name,
    ranked: Vec<&'static str>,
}

/// Check against the allowlist
pub(crate) fn check(query: Name) -> Result<(), Suggestions> {
    if ALLOWED_OTEL_NAMES.contains(query.name) {
        Ok(())
    } else {
        let suggestions = fuzzy_search(
            query.to_string().as_str(),
            ALLOWED_OTEL_NAMES.as_slice(),
            5,
            fuzzy_search::distance::levenshtein,
        );

        Err(Suggestions {
            orig: query,
            ranked: Vec::from_iter(suggestions.into_iter()),
        })
    }
}
