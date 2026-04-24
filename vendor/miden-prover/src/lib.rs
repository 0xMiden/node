#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::ToString, sync::Arc, vec::Vec};

use ::serde::Serialize;
use miden_core::{
    Felt,
    events::{EventId, EventName},
    field::QuadFelt,
    mast::MastForest,
    utils::{Matrix, RowMajorMatrix},
};
use miden_crypto::stark::{
    StarkConfig, air::VarLenPublicInputs, challenger::CanObserve, lmcs::Lmcs, proof::StarkOutput,
};
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    FastProcessor, Program, ProcessorState,
    advice::AdviceMutation,
    event::EventError,
    trace::{AuxTraceBuilders, ExecutionTrace, build_trace},
};
use tracing::instrument;

mod proving_options;

// EXPORTS
// ================================================================================================
pub use miden_air::{DeserializationError, ProcessorAir, PublicInputs, config};
pub use miden_core::proof::{ExecutionProof, HashFunction};
pub use miden_processor::{
    ExecutionError, Host, InputError, StackInputs, StackOutputs, Word, advice::AdviceInputs,
    crypto, field, serde, utils,
};
pub use proving_options::ProvingOptions;

// DYNAMIC HOST SUPPORT
// ================================================================================================

/// Object-safe host trait used by [`prove_dyn_host`] and [`prove_sync_dyn_host`].
///
/// This keeps async proving code monomorphic for host-related call sites while preserving the
/// existing generic [`prove`] API.
pub trait HostDyn: Send {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>);

    fn get_mast_forest_sync(&self, node_digest: &Word) -> Option<Arc<MastForest>>;

    fn on_event_sync_dyn(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> Result<Vec<AdviceMutation>, EventError>;

    fn resolve_event(&self, _event_id: EventId) -> Option<&EventName> {
        None
    }
}

struct HostDynAdapter<'a> {
    inner: &'a mut dyn HostDyn,
}

impl<'a> HostDynAdapter<'a> {
    fn new(inner: &'a mut dyn HostDyn) -> Self {
        Self { inner }
    }
}

impl Host for HostDynAdapter<'_> {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        self.inner.get_label_and_source_file(location)
    }

    fn get_mast_forest(&self, node_digest: &Word) -> impl miden_processor::FutureMaybeSend<Option<Arc<MastForest>>> {
        let result = self.inner.get_mast_forest_sync(node_digest);
        async move { result }
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl miden_processor::FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let result = self.inner.on_event_sync_dyn(process);
        async move { result }
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.inner.resolve_event(event_id)
    }
}

// PROVER
// ================================================================================================

/// Performs STARK proving for a fully built execution trace.
///
/// Kept non-async and marked `inline(never)` so heavy proving codegen stays in this crate and
/// doesn't get pulled into upstream test crates through async call-site monomorphization.
#[inline(never)]
fn prove_built_trace(
    trace: ExecutionTrace,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    tracing::event!(
        tracing::Level::INFO,
        "Generated execution trace of {} columns and {} steps (padded from {})",
        miden_air::trace::TRACE_WIDTH,
        trace.trace_len_summary().padded_trace_len(),
        trace.trace_len_summary().trace_len()
    );

    let stack_outputs = *trace.stack_outputs();
    let precompile_requests = trace.precompile_requests().to_vec();
    let hash_fn = options.hash_fn();

    // Convert trace to row-major format
    let trace_matrix = {
        let _span = tracing::info_span!("to_row_major_matrix").entered();
        trace.to_row_major_matrix()
    };

    // Build public inputs and extract fixed/variable-length components
    let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

    // Get aux trace builders
    let aux_builder = trace.aux_trace_builders();

    // Generate STARK proof using lifted prover
    let params = config::pcs_params();
    let proof_bytes = match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            prove_stark(&config, &trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
        },
    }?;

    let proof = ExecutionProof::new(proof_bytes, hash_fn, precompile_requests);

    Ok((stack_outputs, proof))
}

/// Executes and proves the specified `program` and returns the result together with a STARK-based
/// proof of the program's execution.
///
/// This is an async function that works on all platforms including wasm32.
///
/// - `stack_inputs` specifies the initial state of the stack for the VM.
/// - `host` specifies the host environment which contain non-deterministic (secret) inputs for the
///   prover
/// - `options` defines parameters for STARK proof generation.
///
/// # Errors
/// Returns an error if program execution or STARK proof generation fails for any reason.
#[instrument("prove_program", skip_all)]
pub async fn prove(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    // execute the program to create an execution trace using FastProcessor
    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, *options.execution_options());

    let (execution_output, trace_generation_context) =
        processor.execute_for_trace(program, host).await?;

    let trace = build_trace(execution_output, trace_generation_context, program.to_info())?;
    prove_built_trace(trace, options)
}

/// A dyn-host variant of [`prove`].
#[instrument("prove_program_dyn_host", skip_all)]
pub async fn prove_dyn_host(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut dyn HostDyn,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    let mut host = HostDynAdapter::new(host);

    // execute the program to create an execution trace using FastProcessor
    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, *options.execution_options());

    let (execution_output, trace_generation_context) =
        processor.execute_for_trace(program, &mut host).await?;

    let trace = build_trace(execution_output, trace_generation_context, program.to_info())?;
    prove_built_trace(trace, options)
}

/// Synchronous wrapper for the async `prove()` function.
///
/// This method is only available on non-wasm32 targets. On wasm32, use the
/// async `prove()` method directly since wasm32 runs in the browser's event loop.
///
/// # Panics
/// Panics if called from within an existing Tokio runtime. Use the async `prove()`
/// method instead in async contexts.
#[cfg(not(target_family = "wasm"))]
#[instrument("prove_program_sync", skip_all)]
pub fn prove_sync(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl Host,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            // We're already inside a Tokio runtime - this is not supported
            // because we cannot safely create a nested runtime or move the
            // non-Send host reference to another thread
            panic!(
                "Cannot call prove_sync from within a Tokio runtime. \
                 Use the async prove() method instead."
            )
        },
        Err(_) => {
            // No runtime exists - create one and use it
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(prove(program, stack_inputs, advice_inputs, host, options))
        },
    }
}

/// A dyn-host variant of [`prove_sync`].
#[cfg(not(target_family = "wasm"))]
#[instrument("prove_program_sync_dyn_host", skip_all)]
pub fn prove_sync_dyn_host(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut dyn HostDyn,
    options: ProvingOptions,
) -> Result<(StackOutputs, ExecutionProof), ExecutionError> {
    match tokio::runtime::Handle::try_current() {
        Ok(_handle) => {
            panic!(
                "Cannot call prove_sync_dyn_host from within a Tokio runtime. \
                 Use the async prove_dyn_host() method instead."
            )
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(prove_dyn_host(program, stack_inputs, advice_inputs, host, options))
        },
    }
}

// STARK PROOF GENERATION
// ================================================================================================

/// Generates a STARK proof for the given trace and public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// prover. Returns the serialized proof bytes.
pub fn prove_stark<SC>(
    config: &SC,
    trace: &RowMajorMatrix<Felt>,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    aux_builder: &AuxTraceBuilders,
) -> Result<Vec<u8>, ExecutionError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
{
    let log_trace_height = trace.height().ilog2() as u8;

    let mut challenger = config.challenger();
    challenger.observe_slice(public_values);
    // TODO: observe log_trace_height in the transcript for Fiat-Shamir binding.
    // TODO: observe var_len_public_inputs in the transcript for Fiat-Shamir binding.
    //   This also requires updating the recursive verifier to absorb both fixed and
    //   variable-length public inputs.
    // TODO: observe ACE commitment once ACE verification is integrated.
    // See https://github.com/0xMiden/miden-vm/issues/2822
    let output: StarkOutput<Felt, QuadFelt, SC> = miden_crypto::stark::prover::prove_single(
        config,
        &ProcessorAir,
        trace,
        public_values,
        var_len_public_inputs,
        aux_builder,
        challenger,
    )
    .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    // Proof serialization via bincode; see https://github.com/0xMiden/miden-vm/issues/2550
    // We serialize `(log_trace_height, proof)` as a tuple; this is a temporary approach until
    // the lifted STARK integrates trace height on its side.
    let proof_bytes = bincode::serialize(&(log_trace_height, &output.proof))
        .map_err(|e| ExecutionError::ProvingError(e.to_string()))?;
    Ok(proof_bytes)
}
