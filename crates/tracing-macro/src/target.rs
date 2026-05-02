use syn::{Expr, ExprPath, Path, PathArguments};

pub(crate) fn allowed_targets() -> String {
    miden_node_tracing_targets::allowed_targets_list()
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

    if miden_node_tracing_targets::parse_allowed_target(&target).is_ok() {
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
