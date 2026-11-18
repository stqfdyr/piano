use serde::{Deserialize, Deserializer, de};
use std::fmt;
use std::str::FromStr;

/// A duration written as an integer followed by a unit: `ms`, `s`, `m`, `h` or `d`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(pub std::time::Duration);

/// A duration string that does not follow the `<integer><unit>` form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid duration {0:?}: expected an integer followed by ms, s, m, h or d")]
pub struct ParseDurationError(String);

impl Duration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(std::time::Duration::from_secs(secs))
    }

    pub const fn get(self) -> std::time::Duration {
        self.0
    }
}

impl FromStr for Duration {
    type Err = ParseDurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseDurationError(s.to_owned());
        let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(err)?;
        let (num, unit) = s.split_at(split);
        let n: u64 = num.parse().map_err(|_| err())?;
        let ms_per_unit: u64 = match unit {
            "ms" => 1,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            _ => return Err(err()),
        };
        let ms = n.checked_mul(ms_per_unit).ok_or_else(err)?;
        Ok(Self(std::time::Duration::from_millis(ms)))
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = self.0.as_millis();
        const UNITS: [(u128, &str); 4] = [
            (86_400_000, "d"),
            (3_600_000, "h"),
            (60_000, "m"),
            (1_000, "s"),
        ];
        for (size, unit) in UNITS {
            if ms != 0 && ms.is_multiple_of(size) {
                return write!(f, "{}{unit}", ms / size);
            }
        }
        write!(f, "{ms}ms")
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!("250ms".parse::<Duration>().unwrap().get().as_millis(), 250);
        assert_eq!("5s".parse::<Duration>().unwrap().get().as_secs(), 5);
        assert_eq!("2h".parse::<Duration>().unwrap().get().as_secs(), 7200);
        assert_eq!(
            "30d".parse::<Duration>().unwrap().get().as_secs(),
            30 * 86_400
        );
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "5",
            "s",
            "1.5s",
            "-1s",
            "5 s",
            "5sec",
            "99999999999999999999d",
        ] {
            assert!(s.parse::<Duration>().is_err(), "{s}");
        }
    }

    #[test]
    fn display_round_trips() {
        for s in ["250ms", "5s", "90s", "2m", "2h", "30d", "0ms"] {
            let d: Duration = s.parse().unwrap();
            assert_eq!(d.to_string().parse::<Duration>().unwrap(), d);
        }
    }
}
