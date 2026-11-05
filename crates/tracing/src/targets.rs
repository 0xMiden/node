/// Declares a crate's default tracing target and module-specific overrides.
///
/// Invoke once at the crate root before child module declarations. Configuration expressions
/// retain the caller's scope, and the generated helper resolves targets at compile time. Test
/// builds collect callsites through the tracing crate's inventory and check that every rule is
/// used for the enabled features.
#[macro_export]
#[expect(
    clippy::crate_in_macro_def,
    reason = "The generated helper refers to the registry in the caller's crate."
)]
macro_rules! declare_targets {
    (default: $default:expr, $($(#[$attr:meta])* $module:literal => $target:expr),* $(,)?) => {
        // Evaluate configuration alongside the declaration so caller names and macros keep scope.
        #[doc(hidden)]
        const __MIDEN_TRACING_TARGETS: $crate::TargetMap = $crate::TargetMap::new(
            $default,
            &[$($(#[$attr])* ($module, $target)),*],
        );

        #[doc(hidden)]
        mod __miden_tracing_targets {
            #[cfg(test)]
            use super::__MIDEN_TRACING_TARGETS as TARGETS;

            #[cfg(test)]
            pub(super) struct Callsite {
                pub(super) module: &'static str,
            }

            #[cfg(test)]
            $crate::__private::inventory::collect!(Callsite);

            #[test]
            fn every_target_rule_has_a_compiled_callsite() {
                for (index, (module, _)) in TARGETS.rules().iter().enumerate() {
                    assert!(
                        $crate::__private::inventory::iter::<Callsite>
                            .into_iter()
                            .any(|callsite| TARGETS.matching_rule(callsite.module) == Some(index)),
                        "tracing target rule {} has no compiled callsites",
                        module,
                    );
                }
            }
        }

        macro_rules! tracing_target {
            () => {{
                // Inventory internals otherwise trigger unsafe_derive_deserialize on methods.
                #[cfg(all(test, not(clippy)))]
                $crate::__private::inventory::submit! {
                    crate::__miden_tracing_targets::Callsite { module: module_path!() }
                }

                crate::__MIDEN_TRACING_TARGETS.resolve(module_path!())
            }};
        }
    };
}

/// Maps Rust module subtrees to diagnostic tracing targets.
///
/// The longest matching module prefix wins, independently of rule order. Prefixes match whole
/// module names, so a rule for `node::db` matches `node::db::queries` but not `node::db_backup`.
pub struct TargetMap {
    default: &'static str,
    rules: &'static [(&'static str, &'static str)],
}

impl TargetMap {
    /// Creates a target map with a fallback for modules outside the configured subtrees.
    pub const fn new(
        default: &'static str,
        rules: &'static [(&'static str, &'static str)],
    ) -> Self {
        Self { default, rules }
    }

    /// Resolves the target at compile time for use in static tracing metadata.
    pub const fn resolve(&self, module: &str) -> &'static str {
        match self.matching_rule(module) {
            Some(index) => self.rules[index].1,
            None => self.default,
        }
    }

    /// Returns the configured module prefixes and their diagnostic targets.
    pub const fn rules(&self) -> &'static [(&'static str, &'static str)] {
        self.rules
    }

    /// Returns the index of the most specific rule, or none when the fallback applies.
    pub const fn matching_rule(&self, module: &str) -> Option<usize> {
        let mut best = None;
        let mut longest = 0;
        let mut index = 0;
        while index < self.rules.len() {
            let prefix = self.rules[index].0;
            if prefix.len() > longest && module_matches(module, prefix) {
                best = Some(index);
                longest = prefix.len();
            }
            index += 1;
        }
        best
    }
}

const fn module_matches(module: &str, prefix: &str) -> bool {
    let module = module.as_bytes();
    let prefix = prefix.as_bytes();
    if module.len() < prefix.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if module[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    module.len() == prefix.len()
        || (module.len() > prefix.len() + 1
            && module[prefix.len()] == b':'
            && module[prefix.len() + 1] == b':')
}

#[cfg(test)]
mod tests {
    use super::TargetMap;

    const TARGETS: TargetMap = TargetMap::new(
        "miden::storage",
        &[
            ("node::db::backup", "miden::storage::files"),
            ("node::db", "miden::storage::sqlite"),
        ],
    );

    #[test]
    fn module_subtrees_use_the_most_specific_target() {
        const TARGET: &str = TARGETS.resolve("node::db::backup::writer");
        assert_eq!(TARGET, "miden::storage::files");
        assert_eq!(TARGETS.resolve("node::db"), "miden::storage::sqlite");
        assert_eq!(TARGETS.resolve("node::db::queries"), "miden::storage::sqlite");
    }

    #[test]
    fn unrelated_modules_use_the_default() {
        for module in ["node", "node::db_backup", "node::database", "node::d", "other::db"] {
            assert_eq!(TARGETS.resolve(module), "miden::storage");
        }
    }
}
