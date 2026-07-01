use super::*;

fn valid_body(toml: &str) -> String {
    format!(
        r"## Summary

Changes something.

## Changelog

```toml
{toml}
```
"
    )
}

#[test]
fn accepts_single_entry() {
    let body = valid_body(
        r#"[[entry]]
scope       = "rpc"
impact      = "breaking"
description = "Changed `GetBlockByNumber` to accept a `BlockRequest`."
"#,
    );

    verify_pr_body(&body).unwrap();
}

#[test]
fn accepts_multiple_entries() {
    let body = valid_body(
        r#"[[entry]]
scope       = "rpc"
impact      = "changed"
description = "Changed the RPC response shape."

[[entry]]
scope       = "node"
impact      = "added"
description = "Added a bootstrap command."
"#,
    );

    verify_pr_body(&body).unwrap();
}

#[test]
fn accepts_migration_impact() {
    let body = valid_body(
        r#"[[entry]]
scope       = "node"
impact      = "migration"
description = "Added a storage migration for node databases."
"#,
    );

    verify_pr_body(&body).unwrap();
}

#[test]
fn accepts_validator_and_internal_scopes() {
    let body = valid_body(
        r#"[[entry]]
scope       = "validator"
impact      = "changed"
description = "Changed validator startup behavior."

[[entry]]
scope       = "internal"
impact      = "fixed"
description = "Fixed release automation metadata."
"#,
    );

    verify_pr_body(&body).unwrap();
}

#[test]
fn accepts_no_changelog_marker() {
    let body = valid_body(
        r#"changelog = "none"
reason    = "Internal refactor only."
"#,
    );

    verify_pr_body(&body).unwrap();
}

#[test]
fn ignores_toml_examples_in_html_comments() {
    let body = r#"## Summary

## Changelog

<!--
```toml
changelog = "none"
reason    = "Example only."
```
-->

```toml
[[entry]]
scope       = "docs"
impact      = "fixed"
description = "Fixed the operator migration instructions."
```
"#;

    verify_pr_body(body).unwrap();
}

#[test]
fn accepts_examples_after_changelog_entry() {
    let body = r#"This PR tries out another new changelog system.

## Changelog

```toml
[[entry]]
scope       = "general"
impact      = "added"
description = "changelog is now derived from PR bodies"

# Supports multiple.
# [[entry]]
# scope       = "general"
# impact      = "added"
# description = "changelog is now derived from PR bodies again"
```

or opt out:

```toml
#changelog = "none"
#reason    = "Internal change only."
```

This later code fence is intentionally incomplete and should not affect the
already-parsed changelog block.

```text
"#;

    verify_pr_body(body).unwrap();
}

#[test]
fn rejects_missing_changelog_section() {
    let err = verify_pr_body("## Summary\n\nNo changelog here.\n").unwrap_err();

    assert!(err.to_string().contains("missing `## Changelog` section"));
}

#[test]
fn rejects_missing_toml_block() {
    let err = verify_pr_body("## Changelog\n\nNo block.\n").unwrap_err();

    assert!(err.to_string().contains("missing fenced `toml` block"));
}

#[test]
fn rejects_empty_template_values() {
    let body = valid_body(
        r#"[[entry]]
scope       = ""
impact      = ""
description = ""
"#,
    );

    let err = verify_pr_body(&body).unwrap_err();

    assert!(err.to_string().contains("unknown variant"));
}

#[test]
fn rejects_empty_description() {
    let body = valid_body(
        r#"[[entry]]
scope       = "rpc"
impact      = "changed"
description = ""
"#,
    );

    let err = verify_pr_body(&body).unwrap_err();

    assert!(
        err.to_string()
            .contains("entry 1 field `description` must not be empty")
    );
}

#[test]
fn rejects_unknown_enum_value() {
    let body = valid_body(
        r#"[[entry]]
scope       = "rpc"
impact      = "improved"
description = "Improved RPC behavior."
"#,
    );

    let err = verify_pr_body(&body).unwrap_err();

    assert!(err.to_string().contains("unknown variant `improved`"));
}

#[test]
fn rejects_unknown_fields() {
    let body = valid_body(
        r#"[[entry]]
scope       = "rpc"
impact      = "changed"
description = "Changed RPC behavior."
component   = "rpc"
"#,
    );

    let err = verify_pr_body(&body).unwrap_err();

    assert!(err.to_string().contains("unknown field"));
}
