//! Tiny flag parser shared by the `rfb-testsrv` / `rdp-testsrv` binaries (no clap: keeps the
//! dev crate's tree small). Flags are `--name value` or bare `--switch`.

use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Default)]
pub struct Args {
    values: HashMap<String, String>,
    switches: Vec<String>,
}

impl Args {
    /// Parses `std::env::args()`. `switches` take no value, `values` take one; any other flag
    /// is an error (a typo must not silently start a server with defaults).
    pub fn parse(switches: &[&str], values: &[&str]) -> Result<Self, String> {
        // nosemgrep: rust.lang.security.args.args -- dev-only test-server CLI; argv[0] is skipped and
        // every flag is validated against the allow-lists; no security decision depends on it.
        Self::from_iter(std::env::args().skip(1), switches, values)
    }

    pub fn from_iter(
        it: impl IntoIterator<Item = String>,
        switches: &[&str],
        values: &[&str],
    ) -> Result<Self, String> {
        let mut args = Self::default();
        let mut it = it.into_iter();
        while let Some(a) = it.next() {
            let name = a.strip_prefix("--").ok_or_else(|| format!("unexpected argument {a:?}"))?;
            if switches.contains(&name) {
                args.switches.push(name.to_owned());
            } else if values.contains(&name) {
                let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                args.values.insert(name.to_owned(), v);
            } else {
                return Err(format!("unknown flag --{name}"));
            }
        }
        Ok(args)
    }

    pub fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    pub fn str(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    pub fn get<T: FromStr>(&self, name: &str) -> Result<Option<T>, String> {
        self.str(name)
            .map(|v| v.parse().map_err(|_| format!("bad value for --{name}: {v:?}")))
            .transpose()
    }

    pub fn get_or<T: FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        Ok(self.get(name)?.unwrap_or(default))
    }
}

#[cfg(test)]
mod tests {
    use super::Args;

    #[test]
    fn parses_values_and_switches() {
        let a = Args::from_iter(
            ["--port", "0", "--animate", "--security", "none,vnc"].map(String::from),
            &["animate"],
            &["port", "security"],
        )
        .expect("parse");
        assert_eq!(a.get_or("port", 5900u16), Ok(0));
        assert!(a.has("animate"));
        assert_eq!(a.str("security"), Some("none,vnc"));
        assert!(Args::from_iter(["--port".to_owned()], &[], &["port"]).is_err());
        assert!(Args::from_iter(["--bogus", "1"].map(String::from), &[], &["port"]).is_err());
        assert!(a.get::<u16>("security").is_err());
    }
}
