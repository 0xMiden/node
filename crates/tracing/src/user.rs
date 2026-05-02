use opentelemetry::Key;

// Keep the macro argument transport-agnostic. `user` means "safe to show to an operator"; the
// concrete exporter decides whether that becomes stdout, a UI notification, or something else.
pub(crate) const ATTRIBUTE_KEY: &str = "miden.user";

pub(crate) const FIELD_PREFIX: &str = "miden.user.";
pub(crate) const FIELD_BRIDGE_KEY: &str = "miden.user.fields";

pub(crate) fn field_key(key: impl Into<Key>) -> Key {
    let key = key.into();

    Key::new(format!("{FIELD_PREFIX}{}", key.as_str()))
}

pub(crate) fn format_field(key: &str, value: &str) -> String {
    let key = key.strip_prefix(FIELD_PREFIX).unwrap_or(key);
    let field = format!("{key}={value}");

    format!("{}:{field},", field.len())
}

pub(crate) fn parse_fields(mut fields: &str, mut record: impl FnMut(&str)) {
    while let Some((len, rest)) = fields.split_once(':') {
        let Ok(len) = len.parse::<usize>() else {
            break;
        };
        let Some(field) = rest.get(..len) else {
            break;
        };
        record(field.strip_prefix(FIELD_PREFIX).unwrap_or(field));

        let Some(rest) = rest.get(len..) else {
            break;
        };
        let Some(rest) = rest.strip_prefix(',') else {
            break;
        };
        fields = rest;
    }
}
