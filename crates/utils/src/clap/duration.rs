use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use jiff::SpanRelativeTo;
use jiff::fmt::StdFmtWrite;
use jiff::fmt::friendly::{Designator, SpanParser, SpanPrinter};

/// A duration with a human-readable representation for CLI arguments and logs.
///
/// Days are 24 hours and weeks are seven days.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HumanDuration(Duration);

impl From<Duration> for HumanDuration {
    fn from(duration: Duration) -> Self {
        Self(duration)
    }
}

impl From<HumanDuration> for Duration {
    fn from(duration: HumanDuration) -> Self {
        duration.0
    }
}

impl FromStr for HumanDuration {
    type Err = jiff::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if input == "0" {
            return Ok(Self(Duration::ZERO));
        }

        let parser = SpanParser::new();
        // The unsigned parser covers the full range of Duration. Days and weeks need an explicit
        // conversion because Jiff treats them as calendar units.
        parser
            .parse_unsigned_duration(input)
            .or_else(|_| {
                parser
                    .parse_span(input)?
                    .to_duration(SpanRelativeTo::days_are_24_hours())?
                    .try_into()
            })
            .map(Self)
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        SpanPrinter::new()
            .designator(Designator::HumanTime)
            .print_unsigned_duration(&self.0, StdFmtWrite(f))
            .map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_durations() {
        for (input, expected) in [
            ("0", Duration::ZERO),
            ("250ms", Duration::from_millis(250)),
            ("30m", Duration::from_mins(30)),
            ("1h 30m", Duration::from_mins(90)),
            ("1w 2d", Duration::from_hours(9 * 24)),
        ] {
            assert_eq!(
                Duration::from(input.parse::<HumanDuration>().unwrap()),
                expected,
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_invalid_timeouts() {
        for input in ["-1s", "1M", "1 month", "1 year", "soon"] {
            assert!(input.parse::<HumanDuration>().is_err(), "{input}");
        }
    }

    #[test]
    fn formatted_durations_round_trip() {
        for duration in [Duration::ZERO, Duration::new(3601, 123_456_789), Duration::MAX] {
            let duration = HumanDuration::from(duration);
            assert_eq!(duration.to_string().parse::<HumanDuration>().unwrap(), duration);
        }
    }

    #[test]
    fn grpc_timeout_supports_typed_defaults_and_overrides() {
        use clap::{CommandFactory, Parser};

        use crate::clap::GrpcOptions;

        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            grpc: GrpcOptions,
        }

        let default = Cli::try_parse_from(["node"]).unwrap().grpc;
        assert_eq!(default, GrpcOptions::default());
        assert!(Cli::command().render_long_help().to_string().contains("[default: 10s]"));
        let cli = Cli::try_parse_from(["node", "--grpc.timeout", "1m 30s"]).unwrap();
        assert_eq!(Duration::from(cli.grpc.request_timeout), Duration::from_secs(90));
    }
}
