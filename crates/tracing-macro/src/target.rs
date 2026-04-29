use syn::{Expr, ExprPath, Path, PathArguments};

const ALLOWED_TARGETS: &[&str] = &[
    "rpc",
    "validator::database",
    "store::database",
    "store::forest",
    "store::grpc::server::rpc",
    "store::grpc::server::ntx",
    "store::grpc::server::sequencer",
    "sequencer::batch_builder",
    "sequencer::block_builder",
    "sequencer::mempool",
    "ntxb::coordinator",
    "ntxb::actor",
    "ntxb::database",
];

pub(crate) fn allowed_targets() -> String {
    let mut targets = String::new();
    for target in ALLOWED_TARGETS {
        targets.push_str("\n  - ");
        targets.push_str(target);
    }
    targets
}

pub(crate) fn parse(expr: &Expr) -> syn::Result<String> {
    let target = match expr {
        Expr::Path(ExprPath { qself: None, path, .. }) => parse_path(path)?,
        _ => {
            return Err(syn::Error::new_spanned(
                expr,
                format!(
                    "`target` must be an allowed target path; expected one of: {}",
                    allowed_targets()
                ),
            ));
        },
    };

    if ALLOWED_TARGETS.contains(&target.as_str()) {
        Ok(target)
    } else {
        Err(syn::Error::new_spanned(
            expr,
            format!("unsupported target `{target}`; expected one of: {}", allowed_targets()),
        ))
    }
}

fn parse_path(path: &Path) -> syn::Result<String> {
    if path.leading_colon.is_some() {
        return Err(syn::Error::new_spanned(path, "`target` must be a relative path"));
    }

    path.segments
        .iter()
        .map(|segment| {
            if matches!(segment.arguments, PathArguments::None) {
                Ok(segment.ident.to_string())
            } else {
                Err(syn::Error::new_spanned(
                    &segment.arguments,
                    "`target` path segments cannot have generic arguments",
                ))
            }
        })
        .collect::<syn::Result<Vec<_>>>()
        .map(|segments| segments.join("::"))
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::{allowed_targets, parse};

    #[test]
    fn formats_allowed_targets_as_list() {
        let targets = allowed_targets();

        assert!(targets.starts_with("\n  - rpc"));
        assert!(targets.contains("\n  - ntxb::database"));
    }

    #[test]
    fn parses_allowed_target_path() {
        assert_eq!(parse(&parse_quote!(store::database)).unwrap(), "store::database");
    }

    #[test]
    fn rejects_target_string() {
        let err = parse(&parse_quote!("sequencer::mempool")).unwrap_err();

        assert!(err.to_string().contains("`target` must be an allowed target path"));
    }

    #[test]
    fn rejects_unknown_target_path() {
        let err = parse(&parse_quote!(store::grpc)).unwrap_err();

        assert!(err.to_string().contains("unsupported target `store::grpc`"));
    }

    #[test]
    fn rejects_component_target() {
        let err = parse(&parse_quote!(COMPONENT)).unwrap_err();

        assert!(err.to_string().contains("unsupported target `COMPONENT`"));
    }
}
