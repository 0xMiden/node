use std::collections::BTreeSet;

use proc_macro::TokenStream;
use proc_macro2::{Delimiter, Group, TokenStream as TokenStream2, TokenTree};
use quote::{ToTokens, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Dot;
use syn::visit::Visit;
use syn::{Block, Expr, Ident, ItemFn, Macro, Result, Token, parse_macro_input, parse_quote};

const ALLOWED_FIELD_NAMES: &[&str] = &[
    "account.id",
    "account.id.network_prefix",
    "account.ids",
    "account.ids.count",
    "account.updated",
    "batch.id",
    "batch.account_updates.count",
    "batch.expires_at",
    "batch.expiration_height",
    "batch.input_notes.count",
    "batch.output_notes.count",
    "batch.reference_block.commitment",
    "batch.reference_block.number",
    "block.batch.ids",
    "block.batches.count",
    "block.batches.output_notes.count",
    "block.commitment",
    "block.commitments.account",
    "block.commitments.chain",
    "block.commitments.kernel",
    "block.commitments.note",
    "block.commitments.nullifier",
    "block.commitments.transaction",
    "block.erased_note_proofs.count",
    "block.erased_notes.count",
    "block.from",
    "block.nullifiers.count",
    "block.number",
    "block.output_notes.count",
    "block.prev_block_commitment",
    "block.protocol.version",
    "block.sub_commitment",
    "block.timestamp",
    "block.transactions.ids",
    "block.transactions.count",
    "block.updated_accounts.count",
    "block_range.from",
    "block_range.to",
    "db.account_state_forest.size",
    "db.account_tree.size",
    "db.block_store.size",
    "db.nullifier_tree.size",
    "db.sqlite.size",
    "db.sqlite.wal.size",
    "dice_roll",
    "failure_rate",
    "mempool.accounts",
    "mempool.batches.proposed",
    "mempool.batches.proven",
    "mempool.nullifiers",
    "mempool.output_notes",
    "mempool.transactions.unbatched",
    "mempool.transactions.uncommitted",
    "note.id",
    "notes.count",
    "prover.kind",
    "reference_block.number",
    "request.kind",
    "script.root",
    "transaction.id",
    "transaction.expires_at",
    "transaction.input_notes.count",
    "transaction.output_notes.count",
    "transaction.reference_block.commitment",
    "transaction.reference_block.number",
    "tip.number",
    "transactions.count",
    "transactions.ids",
    "transactions.input_notes.count",
    "transactions.output_notes.count",
    "transactions.unauthenticated_notes.count",
    "workers.active",
    "workers.capacity",
    "workers.count",
];

#[proc_macro_attribute]
pub fn miden_instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = TokenStream2::from(attr);
    let mut function = parse_macro_input!(item as ItemFn);
    let fields = collect_recorded_fields(&function);
    let args = merge_inferred_fields(attr, &fields);
    let statements = &function.block.stmts;
    let block: Block = parse_quote! {{
        #[allow(unused_macros)]
        macro_rules! __miden_span_record_must_be_used_within_miden_instrument {
            () => {};
        }

        #(#statements)*
    }};
    *function.block = block;

    let expanded = quote! {
        #[::tracing::instrument(#args)]
        #function
    };

    expanded.into()
}

fn merge_inferred_fields(attr: TokenStream2, fields: &[FieldPath]) -> TokenStream2 {
    if fields.is_empty() {
        return attr;
    }

    let inferred_fields = quote! { #(#fields = ::tracing::field::Empty),* };
    if attr.is_empty() {
        return quote! { fields(#inferred_fields) };
    }

    let mut merged_existing_fields = false;
    let args = split_top_level_args(attr)
        .into_iter()
        .map(|arg| {
            if let Some(group) = fields_group(&arg) {
                merged_existing_fields = true;
                let existing_fields = group.stream();
                let merged_fields = if existing_fields.is_empty() {
                    inferred_fields.clone()
                } else if ends_with_comma(&existing_fields) {
                    quote! { #existing_fields #inferred_fields }
                } else {
                    quote! { #existing_fields, #inferred_fields }
                };
                let mut merged_group = Group::new(Delimiter::Parenthesis, merged_fields);
                merged_group.set_span(group.span());
                quote! { fields #merged_group }
            } else {
                arg
            }
        })
        .collect::<Vec<_>>();

    if merged_existing_fields {
        quote! { #(#args),* }
    } else {
        quote! { #(#args,)* fields(#inferred_fields) }
    }
}

fn split_top_level_args(tokens: TokenStream2) -> Vec<TokenStream2> {
    let mut args = Vec::new();
    let mut current = TokenStream2::new();

    for token in tokens {
        match &token {
            TokenTree::Punct(punct) if punct.as_char() == ',' => {
                args.push(current);
                current = TokenStream2::new();
            },
            _ => current.extend([token]),
        }
    }

    if !current.is_empty() {
        args.push(current);
    }

    args
}

fn fields_group(arg: &TokenStream2) -> Option<Group> {
    let mut tokens = arg.clone().into_iter();
    let Some(TokenTree::Ident(ident)) = tokens.next() else {
        return None;
    };
    if ident != "fields" {
        return None;
    }

    let Some(TokenTree::Group(group)) = tokens.next() else {
        return None;
    };
    if group.delimiter() != Delimiter::Parenthesis || tokens.next().is_some() {
        return None;
    }

    Some(group)
}

fn ends_with_comma(tokens: &TokenStream2) -> bool {
    matches!(
        tokens.clone().into_iter().last(),
        Some(TokenTree::Punct(punct)) if punct.as_char() == ','
    )
}

#[proc_macro]
pub fn miden_span_record(input: TokenStream) -> TokenStream {
    let records = parse_macro_input!(input as RecordFields);
    let records = records.fields.into_iter().map(|field| {
        let name = field.path.name();
        let value = field.value.value_tokens();

        quote! {
            ::tracing::Span::current().record(#name, #value);
        }
    });

    quote! {
        __miden_span_record_must_be_used_within_miden_instrument!();
        #(#records)*
    }
    .into()
}

fn validate_field_name(path: &FieldPath) -> Result<()> {
    let name = path.name();

    if ALLOWED_FIELD_NAMES.contains(&name.as_str()) {
        Ok(())
    } else {
        Err(syn::Error::new_spanned(
            path,
            format!(
                "unsupported tracing field `{name}`; use one of: {}",
                ALLOWED_FIELD_NAMES.join(", "),
            ),
        ))
    }
}

fn collect_recorded_fields(function: &ItemFn) -> Vec<FieldPath> {
    let mut visitor = MacroVisitor::default();
    visitor.visit_block(&function.block);

    let mut names = BTreeSet::new();
    visitor.fields.into_iter().filter(|field| names.insert(field.name())).collect()
}

#[derive(Default)]
struct MacroVisitor {
    fields: Vec<FieldPath>,
}

impl<'ast> Visit<'ast> for MacroVisitor {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "miden_span_record")
        {
            if let Ok(records) = syn::parse2::<RecordFields>(mac.tokens.clone()) {
                self.fields.extend(records.fields.into_iter().map(|field| field.path));
            }
        }

        syn::visit::visit_macro(self, mac);
    }
}

struct RecordFields {
    fields: Punctuated<RecordField, Token![,]>,
}

impl Parse for RecordFields {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        Ok(Self {
            fields: Punctuated::parse_terminated(input)?,
        })
    }
}

struct RecordField {
    path: FieldPath,
    value: RecordValue,
}

impl Parse for RecordField {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let path = input.parse()?;
        validate_field_name(&path)?;
        input.parse::<Token![=]>()?;
        let value = input.parse()?;

        Ok(Self { path, value })
    }
}

struct FieldPath {
    first: Ident,
    rest: Vec<(Dot, Ident)>,
}

impl FieldPath {
    fn name(&self) -> String {
        std::iter::once(&self.first)
            .chain(self.rest.iter().map(|(_, ident)| ident))
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }
}

impl Parse for FieldPath {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let first = input.parse()?;
        let mut rest = Vec::new();

        while input.peek(Token![.]) {
            rest.push((input.parse()?, input.parse()?));
        }

        Ok(Self { first, rest })
    }
}

impl ToTokens for FieldPath {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        self.first.to_tokens(tokens);
        for (dot, ident) in &self.rest {
            dot.to_tokens(tokens);
            ident.to_tokens(tokens);
        }
    }
}

struct RecordValue {
    formatter: Formatter,
    expr: Expr,
}

impl RecordValue {
    fn value_tokens(&self) -> TokenStream2 {
        let expr = &self.expr;

        match self.formatter {
            Formatter::Display => quote! { &::tracing::field::display(#expr) },
            Formatter::Debug => quote! { &::tracing::field::debug(#expr) },
            Formatter::Plain => quote! { &#expr },
        }
    }
}

impl Parse for RecordValue {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let formatter = if input.peek(Token![%]) {
            input.parse::<Token![%]>()?;
            Formatter::Display
        } else if input.peek(Token![?]) {
            input.parse::<Token![?]>()?;
            Formatter::Debug
        } else {
            Formatter::Plain
        };
        let expr = input.parse()?;

        Ok(Self { formatter, expr })
    }
}

enum Formatter {
    Display,
    Debug,
    Plain,
}
