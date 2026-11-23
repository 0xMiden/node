use std::time::Duration;

use jiff::SpanRelativeTo;
use jiff::fmt::friendly::{Designator, SpanParser, SpanPrinter};

/// Parses a nonnegative timeout or interval. Days are 24 hours and weeks are seven days.
pub fn parse_duration(input: &str) -> Result<Duration, jiff::Error> {
    let input = input.trim();
    if input == "0" {
        return Ok(Duration::ZERO);
    }

    let parser = SpanParser::new();
    // The unsigned parser covers the full range of Duration. Days and weeks need an explicit
    // conversion because Jiff treats them as calendar units.
    parser.parse_unsigned_duration(input).or_else(|_| {
        parser
            .parse_span(input)?
            .to_duration(SpanRelativeTo::days_are_24_hours())?
            .try_into()
    })
}

/// Formats a duration for CLI output and logs.
pub fn format_duration(duration: Duration) -> String {
    SpanPrinter::new()
        .designator(Designator::HumanTime)
        .unsigned_duration_to_string(&duration)
}

/// Leaks a formatted duration for use as a static clap default.
pub fn duration_to_human_readable_string(duration: Duration) -> &'static str {
    format_duration(duration).leak()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_durations() {
        for (input, expected) in [
            ("0", Duration::ZERO),
            ("250ms", Duration::from_millis(250)),
            ("30m", Duration::from_secs(1800)),
            ("1h 30m", Duration::from_secs(5400)),
            ("1w 2d", Duration::from_secs(9 * 24 * 3600)),
        ] {
            assert_eq!(parse_duration(input).unwrap(), expected, "{input}");
        }
    }

    #[test]
    fn rejects_invalid_timeouts() {
        for input in ["-1s", "1M", "1 month", "1 year", "soon"] {
            assert!(parse_duration(input).is_err(), "{input}");
        }
    }

    #[test]
    fn formatted_durations_round_trip() {
        for duration in [Duration::ZERO, Duration::new(3601, 123_456_789), Duration::MAX] {
            assert_eq!(parse_duration(&format_duration(duration)).unwrap(), duration);
        }
    }
}
