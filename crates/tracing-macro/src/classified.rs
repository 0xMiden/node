use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Attribute, Data, DeriveInput, Fields, Ident, Path, Result, Token, Variant};

/// How a variant's failure class is determined.
enum Rule {
    /// The variant is a failure of this class, with the variant's name as the kind.
    Class(Ident),
    /// The variant's field classifies itself.
    Transparent,
    /// The variant's field is an error from a component the node calls.
    Dependency,
    /// A function classifies the variant's field.
    With(Path),
}

pub fn derive_classified(input: &DeriveInput) -> Result<TokenStream> {
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "`Classified` can only be derived for enums",
        ));
    };
    let default = match failure_rule(&input.attrs)? {
        None => format_ident!("Fault"),
        Some(Rule::Class(class)) => class,
        Some(_) => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "an enum's `failure` attribute must be `fault`, `transient` or `rejected`",
            ));
        },
    };

    let arms = data
        .variants
        .iter()
        .map(|variant| {
            let rule =
                failure_rule(&variant.attrs)?.unwrap_or_else(|| Rule::Class(default.clone()));
            variant_arm(variant, rule)
        })
        .collect::<Result<Vec<_>>>()?;

    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics ::miden_node_tracing::Classified for #name #type_generics #where_clause {
            fn failure_class(&self) -> ::miden_node_tracing::FailureClass {
                #[allow(unused_imports)]
                use ::miden_node_tracing::Classified as _;
                match self {
                    #(#arms,)*
                }
            }
        }
    })
}

fn variant_arm(variant: &Variant, rule: Rule) -> Result<TokenStream> {
    let variant_name = &variant.ident;
    if let Rule::Class(class) = rule {
        let kind = snake_case(&variant_name.to_string());
        let pattern = match &variant.fields {
            Fields::Unit => quote! { Self::#variant_name },
            Fields::Unnamed(_) => quote! { Self::#variant_name(..) },
            Fields::Named(_) => quote! { Self::#variant_name { .. } },
        };
        return Ok(quote! { #pattern => ::miden_node_tracing::FailureClass::#class(#kind) });
    }

    let mut fields = variant.fields.iter();
    let (Some(field), None) = (fields.next(), fields.next()) else {
        return Err(syn::Error::new_spanned(
            variant,
            "a variant classified by its field must have exactly one field",
        ));
    };
    let pattern = if let Some(ident) = &field.ident {
        quote! { Self::#variant_name { #ident: __miden_field } }
    } else {
        quote! { Self::#variant_name(__miden_field) }
    };
    let class = match rule {
        Rule::Transparent => quote! { __miden_field.failure_class() },
        Rule::Dependency => quote! {
            ::miden_node_tracing::FailureClass::from_dependency(__miden_field.failure_class())
        },
        Rule::With(path) => quote! { #path(__miden_field) },
        Rule::Class(_) => unreachable!("handled above"),
    };
    Ok(quote! { #pattern => #class })
}

/// Parses a `#[failure(...)]` attribute: `fault`, `transient`, `rejected`, `transparent`,
/// `dependency` or `with = path`.
fn failure_rule(attrs: &[Attribute]) -> Result<Option<Rule>> {
    let mut rule = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("failure")) {
        if rule.is_some() {
            return Err(syn::Error::new_spanned(attr, "duplicate `failure` attribute"));
        }
        rule = Some(attr.parse_args_with(|input: syn::parse::ParseStream<'_>| {
            let ident: Ident = input.parse()?;
            let rule = match ident.to_string().as_str() {
                "fault" => Rule::Class(format_ident!("Fault")),
                "transient" => Rule::Class(format_ident!("Transient")),
                "rejected" => Rule::Class(format_ident!("Rejected")),
                "transparent" => Rule::Transparent,
                "dependency" => Rule::Dependency,
                "with" => {
                    input.parse::<Token![=]>()?;
                    Rule::With(input.parse()?)
                },
                _ => {
                    return Err(syn::Error::new_spanned(
                        ident,
                        "expected `fault`, `transient`, `rejected`, `transparent`, `dependency` \
                         or `with = path`",
                    ));
                },
            };
            Ok(rule)
        })?);
    }
    Ok(rule)
}

/// Converts an `UpperCamelCase` identifier to `snake_case`.
fn snake_case(name: &str) -> String {
    let mut snake = String::with_capacity(name.len() + 4);
    for (index, character) in name.char_indices() {
        if character.is_uppercase() {
            if index > 0 {
                snake.push('_');
            }
            snake.extend(character.to_lowercase());
        } else {
            snake.push(character);
        }
    }
    snake
}
