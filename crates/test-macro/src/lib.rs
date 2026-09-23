use proc_macro::TokenStream;
use quote::ToTokens;
use syn::{Block, ItemFn, parse_macro_input, parse_quote};

#[proc_macro_attribute]
pub fn enable_logging(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut function = parse_macro_input!(item as ItemFn);

    let name = function.sig.ident.to_string();
    let stmts = function.block.stmts;
    let block: Block = parse_quote! {{
        if ::std::env::args().any(|e| e == "--nocapture") {
            if let Err(err) = ::miden_node_tracing::setup_tracing(
                ::miden_node_tracing::OpenTelemetry::Disabled
            ) {
                eprintln!("failed to setup tracing for tests using `enable_logging` proc-macro");
            }
            let span = ::miden_node_tracing::span!(::miden_node_tracing::Level::INFO, #name).entered();

            #(#stmts)*
        } else {
            #(#stmts)*
        }
    }};
    function.block = Box::new(block);

    function.into_token_stream().into()
}
