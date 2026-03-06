use std::str::FromStr;
use std::task::{Context as StdContext, Poll};

use futures::FutureExt;
use futures::future::BoxFuture;
use http::header::{ACCEPT, ToStrError};
use mediatype::{Name, ReadParams};
use miden_node_utils::{ErrorReport, FlattenResult};
use miden_protocol::{Word, WordError};
use semver::{Comparator, Version, VersionReq};
use tower::{Layer, Service};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GenesisNegotiation {
    Optional,
    Mandatory,
}

/// Performs content negotiation by rejecting requests which don't match our RPC version or network.
/// Clients can specify these as parameters in our `application/vnd.miden` accept media range.
///
/// The client can specify RPC versions it supports using the [`VersionReq`] format. The network
/// is specified as the genesis block's commitment. If the server cannot satisfy either of these
/// constraints then the request is rejected.
///
/// Note that both values are optional, as is the header itself. If unset, the server considers
/// any value acceptable.
///
/// As part of the accept header's standard, all media ranges are examined in quality weighting
/// order until a matching content type is found. This means that the client can set multiple
/// `application/vnd.miden` values and each will be tested until one passes. If none pass, the
/// request is rejected.
///
/// ## Format
///
/// Parameters are optional and order is not important.
///
/// ```text
/// application/vnd.miden; version=<version-req>; genesis=0x1234
/// ```
#[derive(Clone)]
pub struct AcceptHeaderLayer {
    supported_versions: VersionReq,
    /// The pre-release label (e.g. `"alpha"` from `"alpha.3"`), or `None` for stable versions.
    /// Only the label is stored so that different pre-release numbers are accepted
    /// (e.g. a server at `alpha.3` accepts clients at `alpha.1`).
    expected_pre_label: Option<String>,
    genesis_commitment: Word,
    /// RPC method names for which the `genesis` parameter is mandatory.
    ///
    /// These should be gRPC method names (e.g. `SubmitProvenTransaction`),
    /// matched against the end of the request path like "/rpc.Api/<method>".
    require_genesis_methods: Vec<&'static str>,
}

#[derive(Debug, thiserror::Error)]
enum AcceptHeaderError {
    #[error("header value could not be parsed as a UTF8 string")]
    InvalidUtf8(#[source] ToStrError),

    #[error("accept header's media type could not be parsed")]
    InvalidMediaType(#[source] mediatype::MediaTypeError),

    #[error("a Q value was invalid")]
    InvalidQValue(#[source] QParsingError),

    #[error("version value failed to parse")]
    InvalidVersion(#[source] semver::Error),

    #[error("genesis value failed to parse")]
    InvalidGenesis(#[source] WordError),

    #[error("server does not support any of the specified application/vnd.miden content types")]
    NoSupportedMediaRange,
}

impl AcceptHeaderLayer {
    pub fn new(rpc_version: &Version, genesis_commitment: Word) -> Self {
        let supported_versions = VersionReq {
            comparators: vec![Comparator {
                op: semver::Op::Exact,
                major: rpc_version.major,
                minor: rpc_version.minor.into(),
                patch: None,
                pre: semver::Prerelease::default(),
            }],
        };

        let expected_pre_label = pre_release_label(&rpc_version.pre);

        AcceptHeaderLayer {
            supported_versions,
            expected_pre_label,
            genesis_commitment,
            require_genesis_methods: Vec::new(),
        }
    }

    /// Mark a gRPC method as requiring a `genesis` parameter in the Accept header.
    pub fn with_genesis_enforced_method(mut self, method: &'static str) -> Self {
        self.require_genesis_methods.push(method);
        self
    }
}

/// Extracts the label portion of a semver pre-release identifier, stripping any trailing
/// numeric segment. For example, `"alpha.3"` returns `Some("alpha")` and `"rc.1"` returns
/// `Some("rc")`. Returns `None` for empty (stable) pre-release identifiers.
fn pre_release_label(pre: &semver::Prerelease) -> Option<String> {
    if pre.is_empty() {
        return None;
    }
    let s = pre.as_str();
    // Strip the trailing `.N` numeric segment if present.
    match s.rsplit_once('.') {
        Some((label, suffix)) if suffix.bytes().all(|b| b.is_ascii_digit()) => {
            Some(label.to_string())
        },
        _ => Some(s.to_string()),
    }
}

impl<S> Layer<S> for AcceptHeaderLayer {
    type Service = AcceptHeaderService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AcceptHeaderService { inner, verifier: self.clone() }
    }
}

impl AcceptHeaderLayer {
    const VERSION: Name<'static> = Name::new_unchecked("version");
    const GENESIS: Name<'static> = Name::new_unchecked("genesis");
    const GRPC: Name<'static> = Name::new_unchecked("grpc");

    /// Parses the `Accept` header's contents, searching for any media type compatible with our
    /// RPC version and genesis commitment, controlling whether `genesis` is optional or mandatory.
    fn negotiate(
        &self,
        accept: &str,
        genesis_mode: GenesisNegotiation,
    ) -> Result<(), AcceptHeaderError> {
        let mut media_types = mediatype::MediaTypeList::new(accept).peekable();

        // Its debatable whether an empty header value is valid. Let's err on the side of being
        // gracious if the client want's to be weird.
        if media_types.peek().is_none() {
            // If there are no media types provided and genesis is required, reject.
            if matches!(genesis_mode, GenesisNegotiation::Mandatory) {
                return Err(AcceptHeaderError::NoSupportedMediaRange);
            }
            return Ok(());
        }

        // Parse media types until we find one we support.
        //
        // Since we only support a single RPC version and a single network, there is no need for
        // fancy content negotiation e.g. searching for the best variation via the quality
        // parameter. We only need to find a single match with any non-zero quality. This simplifies
        // matters quite a bit as tie-breaking is quite complex.
        for media_type in media_types {
            let media_type = media_type.map_err(AcceptHeaderError::InvalidMediaType)?;

            // Skip types that don't match `application/vnd.miden`.
            //
            // Note that `application/*` is invalid so we cannot collapse the conditions.
            match (media_type.ty.as_str(), media_type.subty.as_str()) {
                ("*", "*") | ("*" | "application", "vnd.miden") => {},
                _ => continue,
            }

            // Allow a suffix of grpc.
            //
            // Note that this also serves to obsolete the legacy format of `+grpc.<x.y.z>`.
            if let Some(suffix) = media_type.suffix
                && suffix != Self::GRPC
            {
                continue;
            }

            // Quality value may be set to zero, indicating that the client _does not_ want this
            // media type. So we skip those.
            let quality = media_type
                .get_param(mediatype::names::Q)
                .map(|value| QValue::from_str(value.unquoted_str().as_ref()))
                .transpose()
                .map_err(AcceptHeaderError::InvalidQValue)?
                .unwrap_or_default();

            if quality.is_zero() {
                continue;
            }

            // Skip those that don't match the version requirement.
            //
            // The VersionReq checks major.minor compatibility. Pre-release labels are
            // checked separately because semver's VersionReq matching rejects all
            // pre-release versions when the comparator has no pre-release component.
            let version = media_type
                .get_param(Self::VERSION)
                .map(|value| Version::parse(value.unquoted_str().as_ref()))
                .transpose()
                .map_err(AcceptHeaderError::InvalidVersion)?;
            if let Some(version) = &version {
                // Check major.minor match by stripping pre-release first.
                let stable_version = Version {
                    pre: semver::Prerelease::EMPTY,
                    ..version.clone()
                };
                if !self.supported_versions.matches(&stable_version) {
                    continue;
                }
                // Check the pre-release label matches (ignoring the numeric suffix).
                if pre_release_label(&version.pre) != self.expected_pre_label {
                    continue;
                }
            }

            // Skip if the genesis commitment does not match, or if it is required but missing.
            let genesis = media_type
                .get_param(Self::GENESIS)
                .map(|value| Word::try_from(value.unquoted_str().as_ref()))
                .transpose()
                .map_err(AcceptHeaderError::InvalidGenesis)?;
            match (genesis_mode, genesis) {
                (_, Some(value)) if value != self.genesis_commitment => continue,
                (GenesisNegotiation::Mandatory, None) => continue,
                _ => {},
            }

            // All preconditions met, this is a valid media type that we can serve.
            return Ok(());
        }

        // We've already handled the case where there are no media types specified, so if we are
        // here its because the client _did_ specify some but none of them are a match.
        Err(AcceptHeaderError::NoSupportedMediaRange)
    }
}

/// Service responsible for handling HTTP ACCEPT headers.
#[derive(Clone)]
pub struct AcceptHeaderService<S> {
    inner: S,
    verifier: AcceptHeaderLayer,
}

impl<S, B> Service<http::Request<B>> for AcceptHeaderService<S>
where
    S: Service<http::Request<B>, Response = http::Response<B>> + Clone + Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
    B: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut StdContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        // Skip negotiation entirely for CORS preflight/non-gRPC requests.
        //
        // Browsers often automatically perform an `OPTIONS` check _before_ the client
        // SDK can inject the appropriate `ACCEPT` header, causing a rejection.
        // Since an `OPTIONS` request does nothing its safe for us to simply allow them.
        if request.method() == http::Method::OPTIONS {
            return self.inner.call(request).boxed();
        }

        // Determine if this RPC method requires the `genesis` parameter.
        let path = request.uri().path();
        let method_name = path.rsplit('/').next().unwrap_or_default();

        let requires_genesis = self.verifier.require_genesis_methods.contains(&method_name);

        // If `genesis` is required but the header is missing entirely, reject early.
        let Some(header) = request.headers().get(ACCEPT) else {
            if requires_genesis {
                let response = tonic::Status::invalid_argument(
                    "Accept header with 'genesis' parameter is required for write RPC methods",
                )
                .into_http();
                return futures::future::ready(Ok(response)).boxed();
            }
            return self.inner.call(request).boxed();
        };

        let result = header
            .to_str()
            .map_err(AcceptHeaderError::InvalidUtf8)
            .map(|header| {
                let mode = if requires_genesis {
                    GenesisNegotiation::Mandatory
                } else {
                    GenesisNegotiation::Optional
                };
                self.verifier.negotiate(header, mode)
            })
            .flatten_result();

        match result {
            Ok(()) => self.inner.call(request).boxed(),
            Err(err) => {
                let response = tonic::Status::invalid_argument(err.as_report()).into_http();

                futures::future::ready(Ok(response)).boxed()
            },
        }
    }
}

#[derive(Debug, PartialEq, thiserror::Error)]
enum QParsingError {
    #[error("Q value contained too many decimal digits")]
    TooManyDigits,
    #[error("invalid format")]
    BadFormat,
    #[error("invalid decimal digits")]
    InvalidDecimalDigits,
}

/// Denotes the value of the `Q` parameter which indicates priority of the media-type.
///
/// Has a range of 0..=1 and can have upto three decimal places.
#[derive(Debug, PartialEq)]
struct QValue {
    /// A value in the range `0..=1000` representing the original `Q` value multiplied by 1000.
    kilo: u16,
}

/// As per spec, the default value is 1 if unspecified.
impl Default for QValue {
    fn default() -> Self {
        Self { kilo: 1000 }
    }
}

impl QValue {
    #[cfg(test)]
    const fn new(kilo: u16) -> Self {
        Self { kilo }
    }

    fn is_zero(&self) -> bool {
        self.kilo == 0
    }
}

impl FromStr for QValue {
    type Err = QParsingError;

    /// A [`QValue`] is limited to the `0..=1` range with up to three decimal places.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kilo = match s.as_bytes() {
            // 1
            [b'1'] => 1000,
            // 1. | 1.0 | 1.00 | 1.000
            [b'1', b'.', rest @ ..] if rest.iter().all(|&c| c == b'0') => 1000,
            // 0
            [b'0'] => 0,
            // 0. | 0.x | 0.xy | 0.xyz
            [b'0', b'.', rest @ ..] => {
                // This looks weird but simplifies several things that otherwise become annoying.
                //
                // - `u16::from_str` cannot parse an empty string aka case [].
                // - Because these are fraction digits we need to multiply shorter strings.
                //
                // This recomposition removes the special casing for these.
                let digits = match rest {
                    [] => [b'0', b'0', b'0'],
                    [a] => [*a, b'0', b'0'],
                    [a, b] => [*a, *b, b'0'],
                    [a, b, c] => [*a, *b, *c],
                    _ => return Err(QParsingError::TooManyDigits),
                };

                // SAFETY: This original came from a str and we only pulled off two ascii bytes so
                // the remainder must still be valid utf8.
                let digits = str::from_utf8(&digits).unwrap();
                u16::from_str(digits).map_err(|_| QParsingError::InvalidDecimalDigits)?
            },
            _ => return Err(Self::Err::BadFormat),
        };

        Ok(Self { kilo })
    }
}

// HEADER VERIFICATION TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use semver::Version;

    use super::{AcceptHeaderLayer, QParsingError};
    use crate::server::accept::QValue;

    const TEST_GENESIS_COMMITMENT: &str =
        "0x00000000000000000000000000000000000000000000000000000000deadbeef";
    const TEST_RPC_VERSION: Version = Version::new(0, 2, 3);

    impl AcceptHeaderLayer {
        fn for_tests() -> Self {
            Self::new(&TEST_RPC_VERSION, Word::try_from(TEST_GENESIS_COMMITMENT).unwrap())
        }
    }

    #[rstest::rstest]
    #[case::empty("")]
    #[case::wildcard("*/*")]
    #[case::media_type_only("application/vnd.miden")]
    #[case::with_grpc_suffix("application/vnd.miden+grpc")]
    #[case::with_quality("application/vnd.miden; q=0.3")]
    #[case::version_exact("application/vnd.miden; version=0.2.3")]
    #[case::version_patch_bump("application/vnd.miden; version=0.2.4")]
    #[case::version_patch_down("application/vnd.miden; version=0.2.2")]
    #[case::matching_network(
        "application/vnd.miden; genesis=0x00000000000000000000000000000000000000000000000000000000deadbeef"
    )]
    #[case::matching_network_and_version(
        "application/vnd.miden; genesis=0x00000000000000000000000000000000000000000000000000000000deadbeef; version=0.2.3"
    )]
    #[case::parameter_order_swopped(
        "application/vnd.miden; version=0.2.3; genesis=0x00000000000000000000000000000000000000000000000000000000deadbeef;"
    )]
    #[case::trailing_semi_comma("application/vnd.miden; ")]
    #[case::trailing_comma("application/vnd.miden, ")]
    // This should pass because the 2nd option is valid.
    #[case::multiple_types("application/vnd.miden; version=2.0.0, application/vnd.miden")]
    // Parameter values may be quoted.
    #[case::quoted_quality(r#"application/vnd.miden; q="1""#)]
    #[case::quoted_version(r#"application/vnd.miden; version="0.2.3""#)]
    #[case::quoted_network(r#"application/vnd.miden; genesis="0x00000000000000000000000000000000000000000000000000000000deadbeef""#)]
    #[test]
    fn request_should_pass(#[case] accept: &'static str) {
        AcceptHeaderLayer::for_tests()
            .negotiate(accept, super::GenesisNegotiation::Optional)
            .unwrap();
    }

    #[rstest::rstest]
    #[case::obsolete_format("application/vnd.miden+grpc.0.2.3")]
    #[case::with_non_grpc_suffix("application/vnd.miden+not")]
    #[case::invalid_version("application/vnd.miden; version=0x123")]
    #[case::invalid_genesis("application/vnd.miden; genesis=aaa")]
    #[case::version_too_old("application/vnd.miden; version=0.1.0")]
    #[case::version_too_new("application/vnd.miden; version=0.3.0")]
    #[case::version_prerelease_rejected_by_stable("application/vnd.miden; version=0.2.3-alpha.1")]
    #[case::zero_weighting("application/vnd.miden; q=0.0")]
    #[case::wildcard_subtype("application/*")]
    #[test]
    fn request_should_be_rejected(#[case] accept: &'static str) {
        AcceptHeaderLayer::for_tests()
            .negotiate(accept, super::GenesisNegotiation::Optional)
            .unwrap_err();
    }

    #[test]
    fn write_requires_genesis_param_missing_or_empty_or_mismatch() {
        let layer = AcceptHeaderLayer::for_tests();

        // Missing genesis parameter
        assert!(
            layer
                .negotiate("application/vnd.miden", super::GenesisNegotiation::Mandatory)
                .is_err()
        );

        // Empty header value
        assert!(layer.negotiate("", super::GenesisNegotiation::Mandatory).is_err());

        // Present but mismatched genesis parameter
        let mismatched = "application/vnd.miden; genesis=0x00000000000000000000000000000000000000000000000000000000deadbeee";
        assert!(layer.negotiate(mismatched, super::GenesisNegotiation::Mandatory).is_err());
    }

    #[rstest::rstest]
    #[case::matching_network(
        "application/vnd.miden; genesis=0x00000000000000000000000000000000000000000000000000000000deadbeef"
    )]
    #[case::matching_network_and_version(
        "application/vnd.miden; genesis=0x00000000000000000000000000000000000000000000000000000000deadbeef; version=0.2.3"
    )]
    #[test]
    fn request_with_mandadory_genesis_should_pass(#[case] accept: &'static str) {
        AcceptHeaderLayer::for_tests()
            .negotiate(accept, super::GenesisNegotiation::Mandatory)
            .unwrap();
    }

    #[rstest::rstest]
    #[case::missing_network("application/vnd.miden;")]
    #[case::missing_network_wildcard("*/*")]
    #[test]
    fn request_with_mandadory_genesis_should_be_rejected(#[case] accept: &'static str) {
        AcceptHeaderLayer::for_tests()
            .negotiate(accept, super::GenesisNegotiation::Mandatory)
            .unwrap_err();
    }

    #[rstest::rstest]
    // Success cases
    #[case::one("1", Ok(QValue::new(1_000)))]
    #[case::one_period("1.", Ok(QValue::new(1_000)))]
    #[case::one_full("1.000", Ok(QValue::new(1_000)))]
    #[case::zero("0", Ok(QValue::new(0)))]
    #[case::zero_period("0.", Ok(QValue::new(0)))]
    #[case::zeros("0.000", Ok(QValue::new(0)))]
    #[case::first_decimal("0.1", Ok(QValue::new(100)))]
    #[case::second_decimal("0.01", Ok(QValue::new(10)))]
    #[case::third_decimal("0.001", Ok(QValue::new(1)))]
    #[case::digits_123("0.123", Ok(QValue::new(123)))]
    #[case::digits_456("0.456", Ok(QValue::new(456)))]
    #[case::digits_789("0.789", Ok(QValue::new(789)))]
    // Error cases.
    #[case::too_many_digits("0.1234", Err(QParsingError::TooManyDigits))]
    #[case::invalid_digit("0.a", Err(QParsingError::InvalidDecimalDigits))]
    #[case::extra_period("0..0", Err(QParsingError::InvalidDecimalDigits))]
    #[case::leading_period(".0", Err(QParsingError::BadFormat))]
    #[case::missing_period("0123", Err(QParsingError::BadFormat))]
    #[case::barely_too_large("1.001", Err(QParsingError::BadFormat))]
    #[case::too_large_by_far("2.0", Err(QParsingError::BadFormat))]
    #[test]
    fn qvalue_parsing(#[case] s: &'static str, #[case] expected: Result<QValue, QParsingError>) {
        use std::str::FromStr;

        assert_eq!(QValue::from_str(s), expected);
    }

    #[test]
    fn qvalue_default_is_one() {
        assert_eq!(QValue::default(), QValue::new(1_000));
    }

    mod prerelease {
        use semver::Version;

        use super::*;

        impl AcceptHeaderLayer {
            fn for_prerelease_tests() -> Self {
                let version = Version::parse("0.14.0-alpha.3").unwrap();
                Self::new(&version, Word::try_from(TEST_GENESIS_COMMITMENT).unwrap())
            }
        }

        #[rstest::rstest]
        #[case::empty("")]
        #[case::wildcard("*/*")]
        #[case::media_type_only("application/vnd.miden")]
        #[case::exact_prerelease("application/vnd.miden; version=0.14.0-alpha.3")]
        #[case::different_patch_same_prerelease("application/vnd.miden; version=0.14.1-alpha.3")]
        #[case::different_prerelease_number("application/vnd.miden; version=0.14.0-alpha.1")]
        #[case::different_patch_different_number("application/vnd.miden; version=0.14.2-alpha.5")]
        #[test]
        fn prerelease_should_pass(#[case] accept: &'static str) {
            AcceptHeaderLayer::for_prerelease_tests()
                .negotiate(accept, super::super::GenesisNegotiation::Optional)
                .unwrap();
        }

        #[rstest::rstest]
        #[case::different_prerelease_tag("application/vnd.miden; version=0.14.0-beta.3")]
        #[case::stable_version("application/vnd.miden; version=0.14.0")]
        #[test]
        fn prerelease_should_be_rejected(#[case] accept: &'static str) {
            AcceptHeaderLayer::for_prerelease_tests()
                .negotiate(accept, super::super::GenesisNegotiation::Optional)
                .unwrap_err();
        }
    }
}
