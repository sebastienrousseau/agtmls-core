// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Index and feed signatures (agtmls-spec chapter 9).
//!
//! An `SSHSIG` over the exact bytes of a file, judged against an
//! `allowed_signers` file for one principal and one namespace. Verification
//! is delegated to `ssh-keygen -Y verify`, which spec 9.5 permits: it is the
//! tool the vectors are checked against, so there is no second reading of
//! the format to drift from it.

use std::fmt;
use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};

/// The principal every release key is listed under.
pub const PRINCIPAL: &str = "agtmls-release";
/// The namespace of an `index.json` signature.
pub const INDEX_NAMESPACE: &str = "agtmls-index@v1";
/// The namespace of an `advisories.json` signature.
pub const ADVISORY_NAMESPACE: &str = "agtmls-advisory@v1";

/// What a verification concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The signature verifies for the principal, namespace and time.
    Verified,
    /// A signature exists and does not verify: tampered bytes, an unknown
    /// signer, the wrong namespace, or a key outside its window.
    BadSignature,
    /// There is no signature, or no `allowed_signers` to judge it by.
    Unsigned,
}

impl Status {
    /// The spelling the spec vectors and both implementations use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::BadSignature => "bad_signature",
            Self::Unsigned => "unsigned",
        }
    }
}

/// Why nothing could be concluded. Never a verdict.
#[derive(Debug)]
pub enum VerifyError {
    /// `ssh-keygen` could not be run.
    ToolMissing(std::io::Error),
    /// The signed file could not be read.
    Io(std::io::Error),
    /// A verification time that is not `YYYYMMDD`.
    BadTime(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolMissing(e) => {
                write!(
                    f,
                    "ssh-keygen could not be run ({e}); signatures cannot be verified"
                )
            }
            Self::Io(e) => write!(f, "the signed file could not be read: {e}"),
            Self::BadTime(t) => write!(f, "verify time {t:?} is not YYYYMMDD"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Whether `value` is a `YYYYMMDD` verification time. Checked before it
/// reaches `ssh-keygen`, which would otherwise read it as an option.
#[must_use]
pub fn is_verify_time(value: &str) -> bool {
    value.len() == 8 && value.bytes().all(|b| b.is_ascii_digit())
}

/// Verify `signature` over the exact bytes of `data` (spec 9.5).
///
/// No signature file, or no `allowed_signers`, is [`Status::Unsigned`]:
/// there is nothing to verify, which is not the same as a signature that
/// fails. `verify_time` (`YYYYMMDD`) replaces the current time, which is how
/// the spec's vectors stay valid.
///
/// # Errors
/// [`VerifyError`] when `ssh-keygen` cannot be run, `data` cannot be read, or
/// `verify_time` is malformed.
pub fn verify(
    data: &Path,
    signature: &Path,
    allowed_signers: &Path,
    namespace: &str,
    principal: &str,
    verify_time: Option<&str>,
) -> Result<Status, VerifyError> {
    if let Some(time) = verify_time {
        if !is_verify_time(time) {
            return Err(VerifyError::BadTime(time.to_owned()));
        }
    }
    if !signature.is_file() || !allowed_signers.is_file() {
        return Ok(Status::Unsigned);
    }
    let input = File::open(data).map_err(VerifyError::Io)?;
    let mut command = Command::new("ssh-keygen");
    command
        .args(["-Y", "verify", "-f"])
        .arg(allowed_signers)
        .args(["-I", principal, "-n", namespace, "-s"])
        .arg(signature);
    if let Some(time) = verify_time {
        command.arg(format!("-Overify-time={time}"));
    }
    let status = command
        .stdin(input)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(VerifyError::ToolMissing)?;
    Ok(if status.success() {
        Status::Verified
    } else {
        Status::BadSignature
    })
}

#[cfg(test)]
mod tests {
    use super::{Status, is_verify_time, verify};
    use std::path::Path;

    #[test]
    fn verify_time_is_eight_digits() {
        assert!(is_verify_time("20260924"));
        assert!(!is_verify_time("2026-09-24"));
        assert!(!is_verify_time("-Oprint"));
        assert!(!is_verify_time("2026092"));
    }

    #[test]
    fn a_malformed_time_is_an_error_not_a_verdict() {
        let missing = Path::new("/nonexistent");
        assert!(verify(missing, missing, missing, "n", "p", Some("x")).is_err());
    }

    #[test]
    fn nothing_to_verify_is_unsigned() {
        let missing = Path::new("/nonexistent/agtmls");
        assert_eq!(
            verify(missing, missing, missing, "n", "p", None).expect("no tool needed"),
            Status::Unsigned
        );
    }
}
