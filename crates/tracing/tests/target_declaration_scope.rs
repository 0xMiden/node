use miden_node_tracing::instrument_v2;

const DEFAULT_TARGET: &str = "miden::default";
const DATABASE_TARGET: &str = "miden::database";

miden_node_tracing::declare_targets! {
    default: DEFAULT_TARGET,
    "target_declaration_scope::database" => DATABASE_TARGET,
    "target_declaration_scope::context" => module_path!(),
}

#[instrument_v2]
fn default_target() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

mod database {
    #[miden_node_tracing::instrument_v2]
    pub fn target() -> &'static str {
        tracing::Span::current().metadata().unwrap().target()
    }
}

mod context {
    #[miden_node_tracing::instrument_v2]
    pub fn target() -> &'static str {
        tracing::Span::current().metadata().unwrap().target()
    }
}

#[test]
fn configuration_expressions_keep_the_declaration_scope() {
    tracing::subscriber::with_default(tracing_subscriber::registry(), || {
        assert_eq!(default_target(), DEFAULT_TARGET);
        assert_eq!(database::target(), DATABASE_TARGET);
        assert_eq!(context::target(), module_path!());
    });
}
