//! Packages as advisory databases name them.

use std::borrow::Cow;
use std::str::FromStr;

use serde::Serialize;

/// A package ecosystem, as OSV names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ecosystem {
    /// Rust crates (`Cargo.lock`, `cargo install`).
    CratesIo,
    /// npm packages (`package-lock.json`, `npm install -g`).
    Npm,
    /// Python packages (`uv.lock`, `poetry.lock`, uv and pipx tools).
    PyPI,
    /// Go modules.
    Go,
    /// Ruby gems.
    RubyGems,
    /// GitHub Actions used by workflows.
    GitHubActions,
    /// Debian packages of one stable release (`Debian:12`), by source package name.
    Debian {
        /// The major release number.
        release: u16,
    },
    /// Ubuntu packages of one release (`Ubuntu:24.04:LTS`), by source package name.
    Ubuntu {
        /// The release year, two digits.
        year: u8,
        /// The release month.
        month: u8,
    },
    /// Alpine packages of one release (`Alpine:v3.20`), by origin (source) package name.
    Alpine {
        /// The major release number.
        major: u8,
        /// The minor release number.
        minor: u8,
    },
}

impl Ecosystem {
    /// The language ecosystems, the ones [`FromStr`] parses, in declaration order.
    const ALL: [Self; 6] = [
        Self::CratesIo,
        Self::Npm,
        Self::PyPI,
        Self::Go,
        Self::RubyGems,
        Self::GitHubActions,
    ];

    /// Returns OSV's name for the ecosystem, as used in its API and records.
    ///
    /// Release suffixes follow the OSV schema's ecosystem list
    /// (<https://ossf.github.io/osv-schema/#affectedpackage-field>, checked 2026-11-06): Ubuntu
    /// adds `:LTS` for long-term releases, which are the April releases of even years.
    pub fn osv_name(self) -> Cow<'static, str> {
        match self {
            Self::CratesIo => "crates.io".into(),
            Self::Npm => "npm".into(),
            Self::PyPI => "PyPI".into(),
            Self::Go => "Go".into(),
            Self::RubyGems => "RubyGems".into(),
            Self::GitHubActions => "GitHub Actions".into(),
            Self::Debian { release } => format!("Debian:{release}").into(),
            Self::Ubuntu { year, month } => {
                let lts = if year % 2 == 0 && month == 4 {
                    ":LTS"
                } else {
                    ""
                };
                format!("Ubuntu:{year:02}.{month:02}{lts}").into()
            }
            Self::Alpine { major, minor } => format!("Alpine:v{major}.{minor}").into(),
        }
    }

    /// Returns whether OSV is asked about the installed version rather than every advisory for
    /// the name: true for OS packages. A Debian or Ubuntu package's name alone matches every
    /// advisory of every release (266 for Debian's `openssl`, over 1000 for `linux`, checked
    /// 2026-11-06), and OSV compares dpkg and apk versions as each distribution does, which the
    /// agent would otherwise have to do by hand.
    pub fn queried_by_version(self) -> bool {
        match self {
            Self::CratesIo
            | Self::Npm
            | Self::PyPI
            | Self::Go
            | Self::RubyGems
            | Self::GitHubActions => false,
            Self::Debian { .. } | Self::Ubuntu { .. } | Self::Alpine { .. } => true,
        }
    }
}

/// Serialized as OSV's name, the same string the OSV API is sent.
impl Serialize for Ecosystem {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.osv_name())
    }
}

impl FromStr for Ecosystem {
    type Err = ParsePackageError;

    /// Parses OSV's name for a language ecosystem, ignoring case. OS ecosystems come only from a
    /// server's own release file.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|e| e.osv_name().eq_ignore_ascii_case(s))
            .ok_or(ParsePackageError::Ecosystem)
    }
}

/// A package in one ecosystem. Versions are deliberately absent: advisories are looked up by
/// name, and each advisory is compared with the installed version later (`matching`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Package {
    /// The ecosystem the name belongs to.
    pub ecosystem: Ecosystem,
    /// The package name as the ecosystem spells it (`@scope/name`, `golang.org/x/net`).
    pub name: String,
}

impl FromStr for Package {
    type Err = ParsePackageError;

    /// Parses `ecosystem:name`, such as `npm:lodash` or `crates.io:serde`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ecosystem, name) = s.split_once(':').ok_or(ParsePackageError::NoColon)?;
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(ParsePackageError::Name);
        }
        Ok(Self {
            ecosystem: ecosystem.parse()?,
            name: name.to_owned(),
        })
    }
}

/// Why a string is not an `ecosystem:name` package.
#[derive(Debug, thiserror::Error)]
pub enum ParsePackageError {
    /// There is no `:` between ecosystem and name.
    #[error("expected ecosystem:name, such as npm:lodash")]
    NoColon,
    /// The ecosystem is not one Vigil knows.
    #[error("unknown ecosystem; use crates.io, npm, PyPI, Go, RubyGems or GitHub Actions")]
    Ecosystem,
    /// The name is empty or has control characters.
    #[error("package name must be non-empty without control characters")]
    Name,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays_packages() {
        for (text, ecosystem, name) in [
            ("npm:@scope/pkg", Ecosystem::Npm, "@scope/pkg"),
            ("crates.io:serde", Ecosystem::CratesIo, "serde"),
            ("pypi:Django", Ecosystem::PyPI, "Django"),
            ("Go:golang.org/x/net", Ecosystem::Go, "golang.org/x/net"),
            ("RubyGems:rails", Ecosystem::RubyGems, "rails"),
            (
                "GitHub Actions:actions/checkout",
                Ecosystem::GitHubActions,
                "actions/checkout",
            ),
        ] {
            let package: Package = text.parse().unwrap();
            assert_eq!(package.ecosystem, ecosystem, "{text}");
            assert_eq!(package.name, name, "{text}");
        }
    }

    #[test]
    fn serializes_with_osv_names() {
        let json = serde_json::to_string(
            &"GitHub Actions:actions/checkout"
                .parse::<Package>()
                .unwrap(),
        );
        assert_eq!(
            json.unwrap(),
            r#"{"ecosystem":"GitHub Actions","name":"actions/checkout"}"#
        );
        for ecosystem in Ecosystem::ALL {
            let json = serde_json::to_string(&ecosystem).unwrap();
            assert_eq!(json, format!("{:?}", ecosystem.osv_name()));
        }
    }

    #[test]
    fn os_ecosystems_carry_their_release_and_are_queried_by_version() {
        let cases = [
            (Ecosystem::Debian { release: 12 }, "Debian:12"),
            (Ecosystem::Ubuntu { year: 24, month: 4 }, "Ubuntu:24.04:LTS"),
            (
                Ecosystem::Ubuntu {
                    year: 22,
                    month: 10,
                },
                "Ubuntu:22.10",
            ),
            (Ecosystem::Ubuntu { year: 23, month: 4 }, "Ubuntu:23.04"),
            (Ecosystem::Alpine { major: 3, minor: 9 }, "Alpine:v3.9"),
        ];
        for (ecosystem, name) in cases {
            assert_eq!(ecosystem.osv_name(), name);
            assert!(ecosystem.queried_by_version(), "{name}");
            assert_eq!(
                serde_json::to_string(&ecosystem).unwrap(),
                format!("{name:?}")
            );
        }
        for ecosystem in Ecosystem::ALL {
            assert!(!ecosystem.queried_by_version(), "{ecosystem:?}");
        }
        assert!("Debian:12".parse::<Ecosystem>().is_err());
    }

    #[test]
    fn rejects_bad_packages() {
        assert!(matches!(
            "lodash".parse::<Package>(),
            Err(ParsePackageError::NoColon)
        ));
        assert!(matches!(
            "cargo:serde".parse::<Package>(),
            Err(ParsePackageError::Ecosystem)
        ));
        assert!(matches!(
            "npm:".parse::<Package>(),
            Err(ParsePackageError::Name)
        ));
        assert!(matches!(
            "npm:a\nb".parse::<Package>(),
            Err(ParsePackageError::Name)
        ));
    }
}
