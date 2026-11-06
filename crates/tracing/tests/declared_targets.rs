miden_node_tracing::declare_targets! {
    default: "inventory::shared",
    "declared_targets::unexecuted" => "inventory::unexecuted",
    "declared_targets::duplicate" => "inventory::shared",
    #[cfg(any())]
    "declared_targets::excluded" => "inventory::excluded",
}

mod unexecuted {
    #[expect(dead_code, reason = "Target discovery must not require executing this function.")]
    pub fn emit() {
        miden_node_tracing::info_v2!("unexecuted");
    }
}

mod duplicate {
    #[expect(dead_code, reason = "Target discovery must not require executing this function.")]
    pub fn emit() {
        miden_node_tracing::info_v2!("duplicate");
    }
}

#[test]
fn declarations_are_available_without_executing_callsites() {
    assert_eq!(
        miden_node_tracing::declared_targets(),
        vec![
            "inventory::shared",
            "inventory::unexecuted",
            "miden::rpc::server",
            "miden::tracing"
        ],
    );
}
