use quote::quote;
use syn::{Expr, ExprLit, ExprPath, Lit, PathArguments};

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
            Expr::Lit(ExprLit { lit: Lit::Str(lit), .. }) => Self::parse_str(&lit.value(), expr),
            Expr::Path(ExprPath { qself: None, path, .. }) => {
                let segment = path.segments.last().ok_or_else(|| {
                    syn::Error::new_spanned(expr, "`level` path must not be empty")
                })?;
                if !matches!(segment.arguments, PathArguments::None) {
                    return Err(syn::Error::new_spanned(
                        &segment.arguments,
                        "`level` path segments cannot have generic arguments",
                    ));
                }

                Self::parse_str(&segment.ident.to_string(), expr)
            },
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

    fn parse_str(level: &str, span: impl quote::ToTokens) -> syn::Result<Self> {
        match level.to_ascii_lowercase().as_str() {
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
