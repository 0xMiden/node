use syn::{Expr, ExprLit, Lit};

pub(crate) fn parse(expr: &Expr) -> syn::Result<String> {
    let Expr::Lit(ExprLit { lit: Lit::Str(value), .. }) = expr else {
        return Err(syn::Error::new_spanned(
            expr,
            "`name` must be a string literal, such as \"rpc::get_block\"",
        ));
    };
    let name = value.value();

    if name.trim().is_empty() {
        return Err(syn::Error::new_spanned(value, "`name` must not be empty"));
    }

    Ok(name)
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::parse;

    #[test]
    fn parses_string_name() {
        assert_eq!(parse(&parse_quote!("rpc::get_block")).unwrap(), "rpc::get_block");
    }

    #[test]
    fn parses_name_with_spaces() {
        assert_eq!(parse(&parse_quote!("db insert")).unwrap(), "db insert");
    }

    #[test]
    fn rejects_empty_name() {
        let err = parse(&parse_quote!("")).unwrap_err();

        assert!(err.to_string().contains("`name` must not be empty"));
    }

    #[test]
    fn rejects_name_path() {
        let err = parse(&parse_quote!(rpc::get_block)).unwrap_err();

        assert!(err.to_string().contains("`name` must be a string literal"));
    }
}
