//! Libsodium version functions

use std::str;

/// `version_string()` returns the version string from libsodium.
pub fn version_string() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"))
}

/// `version_major()` returns the major version from libsodium.
pub fn version_major() -> usize {
    0
}

/// `version_minor()` returns the minor version from libsodium.
pub fn version_minor() -> usize {
    0
}

#[cfg(test)]
mod test {
    #[test]
    fn test_version_string() {
        use crate::version::version_string;
        assert!(!version_string().is_empty());
    }
}
