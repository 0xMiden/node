use syn::{Expr, ExprPath, Path, PathArguments};

pub(crate) fn parse(expr: &Expr) -> syn::Result<String> {
    match expr {
        Expr::Path(ExprPath { qself: None, path, .. }) => parse_path(path),
        _ => Err(syn::Error::new_spanned(expr, "`name` must be a path, such as `rpc::get_block`")),
    }
}

fn parse_path(path: &Path) -> syn::Result<String> {
    if path.leading_colon.is_some() {
        return Err(syn::Error::new_spanned(path, "`name` must be a relative path"));
    }

    let segments = path
        .segments
        .iter()
        .map(|segment| {
            if matches!(segment.arguments, PathArguments::None) {
                Ok(segment.ident.to_string())
            } else {
                Err(syn::Error::new_spanned(
                    &segment.arguments,
                    "`name` path segments cannot have generic arguments",
                ))
            }
        })
        .collect::<syn::Result<Vec<_>>>()?;

    if segments.is_empty() {
        return Err(syn::Error::new_spanned(path, "`name` path must not be empty"));
    }

    Ok(segments.join("::"))
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::parse;

    #[test]
    fn parses_name_path_as_rust_path_name() {
        assert_eq!(parse(&parse_quote!(rpc::get_block)).unwrap(), "rpc::get_block");
    }

    #[test]
    fn parses_single_segment_name_path() {
        assert_eq!(parse(&parse_quote!(get_block)).unwrap(), "get_block");
    }

    #[test]
    fn rejects_name_string() {
        let err = parse(&parse_quote!("rpc::get_block")).unwrap_err();

        assert!(err.to_string().contains("`name` must be a path"));
    }

    #[test]
    fn rejects_absolute_name_path() {
        let err = parse(&parse_quote!(::rpc::get_block)).unwrap_err();

        assert!(err.to_string().contains("`name` must be a relative path"));
    }
}
