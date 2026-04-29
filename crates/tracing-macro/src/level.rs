use quote::quote;
use syn::{Expr, ExprPath, Path, PathArguments};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpanLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl SpanLevel {
    pub(crate) fn parse(expr: &Expr) -> syn::Result<Self> {
        match expr {
            Expr::Path(ExprPath { qself: None, path, .. }) => Self::parse_path(path, expr),
            _ => Err(syn::Error::new_spanned(
                expr,
                "`level` must be one of: trace, debug, info, warn, error",
            )),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    pub(crate) fn metadata_tokens(self) -> proc_macro2::TokenStream {
        match self {
            Self::Trace => quote! { ::miden_node_tracing::SpanLevel::Trace },
            Self::Debug => quote! { ::miden_node_tracing::SpanLevel::Debug },
            Self::Info => quote! { ::miden_node_tracing::SpanLevel::Info },
            Self::Warn => quote! { ::miden_node_tracing::SpanLevel::Warn },
            Self::Error => quote! { ::miden_node_tracing::SpanLevel::Error },
        }
    }

    pub(crate) fn tracing_tokens(self) -> proc_macro2::TokenStream {
        match self {
            Self::Trace => quote! { ::miden_node_tracing::tracing::Level::TRACE },
            Self::Debug => quote! { ::miden_node_tracing::tracing::Level::DEBUG },
            Self::Info => quote! { ::miden_node_tracing::tracing::Level::INFO },
            Self::Warn => quote! { ::miden_node_tracing::tracing::Level::WARN },
            Self::Error => quote! { ::miden_node_tracing::tracing::Level::ERROR },
        }
    }

    pub(crate) const fn tracing_name(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    fn parse_path(path: &Path, span: impl quote::ToTokens) -> syn::Result<Self> {
        if path.leading_colon.is_some() {
            return Err(syn::Error::new_spanned(path, "`level` must be a relative path"));
        }

        let mut segments = path.segments.iter();
        let Some(segment) = segments.next() else {
            return Err(syn::Error::new_spanned(path, "`level` path must not be empty"));
        };
        if segments.next().is_some() {
            return Err(syn::Error::new_spanned(
                path,
                "`level` must be one of: trace, debug, info, warn, error",
            ));
        }
        if !matches!(segment.arguments, PathArguments::None) {
            return Err(syn::Error::new_spanned(
                &segment.arguments,
                "`level` path segments cannot have generic arguments",
            ));
        }

        Self::parse_str(&segment.ident.to_string(), span)
    }

    fn parse_str(level: &str, span: impl quote::ToTokens) -> syn::Result<Self> {
        match level {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(syn::Error::new_spanned(
                span,
                "`level` must be one of: trace, debug, info, warn, error",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::SpanLevel;

    #[test]
    fn parses_level_path() {
        assert_eq!(SpanLevel::parse(&parse_quote!(debug)).unwrap(), SpanLevel::Debug);
    }

    #[test]
    fn rejects_level_string() {
        let err = SpanLevel::parse(&parse_quote!("debug")).unwrap_err();

        assert!(err.to_string().contains("`level` must be one of"));
    }

    #[test]
    fn rejects_qualified_level_path() {
        let err = SpanLevel::parse(&parse_quote!(tracing::Level::DEBUG)).unwrap_err();

        assert!(err.to_string().contains("`level` must be one of"));
    }

    #[test]
    fn rejects_uppercase_level_path() {
        let err = SpanLevel::parse(&parse_quote!(DEBUG)).unwrap_err();

        assert!(err.to_string().contains("`level` must be one of"));
    }
}
