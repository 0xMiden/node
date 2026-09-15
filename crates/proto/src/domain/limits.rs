#![expect(
    clippy::implicit_hasher,
    reason = "decoded maps use the same hasher as Prost maps"
)]

use std::collections::HashMap;

use miden_protobuf::{ConversionError, ConversionResultExt, DecodeMessage};

use crate::generated::rpc::{EndpointLimits, RpcLimits};

impl DecodeMessage for EndpointLimits {
    type Decoded = HashMap<String, u32>;
}

impl TryFrom<EndpointLimits> for HashMap<String, u32> {
    type Error = ConversionError;

    fn try_from(value: EndpointLimits) -> Result<Self, Self::Error> {
        Ok(value.parameters)
    }
}

impl DecodeMessage for RpcLimits {
    type Decoded = HashMap<String, HashMap<String, u32>>;
}

impl TryFrom<RpcLimits> for HashMap<String, HashMap<String, u32>> {
    type Error = ConversionError;

    fn try_from(value: RpcLimits) -> Result<Self, Self::Error> {
        value
            .endpoints
            .into_iter()
            .map(|(name, limits)| {
                let limits =
                    limits.decode_fields().with_context(|| format!("endpoints[{name:?}]"))?;
                Ok((name, limits))
            })
            .collect()
    }
}
