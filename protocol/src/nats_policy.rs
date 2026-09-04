//! Policy for NATS server URLs: TLS past the local host.
//!
//! The NATS password authorizes the approval control plane, so a plaintext
//! `nats://` URL to a non-loopback host would send it and every control
//! message without transport security. `tls://` passes anywhere with the
//! client's normal certificate validation (system roots, hostname check);
//! `nats://` passes only for a loopback host, or with the explicit testing
//! opt-out below. Anything else is rejected before any credential leaves
//! the process.

use std::net::IpAddr;

use crate::Error;

/// Opts one host out of the TLS requirement. Testing and loopback-adjacent
/// development only (the Compose `nats` hostname, a tailnet address without
/// a server certificate yet); production connections use `tls://`.
pub const ALLOW_PLAINTEXT_NATS_ENV: &str = "OSHIOKI_ALLOW_PLAINTEXT_NATS";

/// Truthy values for the opt-out: `1`, `true`, or `yes` in any letter case
/// around optional whitespace. Anything else, including unset, means TLS.
pub fn allow_plaintext_nats(value: Option<&str>) -> bool {
    matches!(
        value.map(|value| value.trim().to_lowercase()).as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Whether `host` is unambiguously this machine: empty (a bare port, which
/// connects locally), `localhost`, or a loopback IP literal. Hostnames are
/// matched literally and never resolved: resolution can change between the
/// check and the connection, and offline hosts must fail the same way.
fn is_loopback_host(host: &str) -> bool {
    if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The host part of the URL after the scheme: userinfo, port, path, query,
/// and fragment stripped, brackets removed from IPv6 literals.
fn nats_url_host(after_scheme: &str) -> Option<&str> {
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    if let Some(bracketed) = host_port.strip_prefix('[') {
        return bracketed.split(']').next();
    }
    host_port.split(':').next()
}

/// Rejects a NATS server URL that would send credentials and control
/// messages in plaintext past the local host. `allow_plaintext` is the
/// parsed [`ALLOW_PLAINTEXT_NATS_ENV`] opt-out from the caller's own config
/// source (process environment for the server and agent, `config.env` for
/// the hook, whose sudo environment is scrubbed).
pub fn check_nats_url(url: &str, allow_plaintext: bool) -> Result<(), Error> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        Error::InvalidConfig("NATS URL has no scheme (want nats:// or tls://)".into())
    })?;
    if scheme.eq_ignore_ascii_case("tls") {
        return Ok(());
    }
    if !scheme.eq_ignore_ascii_case("nats") {
        return Err(Error::InvalidConfig(format!(
            "unsupported NATS URL scheme {scheme:?} (want nats:// or tls://)"
        )));
    }
    let host =
        nats_url_host(rest).ok_or_else(|| Error::InvalidConfig("NATS URL has no host".into()))?;
    if is_loopback_host(host) || allow_plaintext {
        return Ok(());
    }
    Err(Error::InvalidConfig(format!(
        "refusing plaintext nats:// to non-loopback host {host:?}: use tls://, \
         or set {ALLOW_PLAINTEXT_NATS_ENV}=1 for testing only"
    )))
}

/// Whether the URL selects TLS. Callers pass this to
/// `ConnectOptions::require_tls` so servers the cluster discovers later
/// cannot downgrade a `tls://` deployment: discovered addresses arrive as
/// bare `host:port`, which parse as plaintext, and the options flag is the
/// only thing forcing TLS on them.
pub fn nats_url_is_tls(url: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("tls"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tls_probe_follows_the_scheme() {
        assert!(nats_url_is_tls("tls://nats.example.com:4222"));
        assert!(nats_url_is_tls("TLS://nats.example.com:4222"));
        assert!(!nats_url_is_tls("nats://nats.example.com:4222"));
        assert!(!nats_url_is_tls("nats://127.0.0.1:4222"));
        assert!(!nats_url_is_tls("nats.example.com:4222"));
    }

    #[test]
    fn tls_passes_anywhere() {
        for url in [
            "tls://nats.example.com:4222",
            "tls://100.64.0.1:4222",
            "tls://192.168.1.5:4222",
            "tls://nats:4222",
            "tls://127.0.0.1:4222",
            "TLS://nats.example.com:4222",
        ] {
            check_nats_url(url, false).unwrap();
        }
    }

    #[test]
    fn loopback_plaintext_passes_without_the_opt_out() {
        for url in [
            "nats://127.0.0.1:4222",
            "nats://127.0.0.2:4222",
            "nats://localhost:4222",
            "nats://LOCALHOST:4222",
            "nats://[::1]:4222",
            "nats://user:pass@127.0.0.1:4222",
            "nats://:4222",
            "NATS://127.0.0.1:4222",
        ] {
            check_nats_url(url, false).unwrap();
        }
    }

    #[test]
    fn non_loopback_plaintext_needs_the_opt_out() {
        for url in [
            "nats://100.64.0.1:4222",
            "nats://nats:4222",
            "nats://nats.example.com:4222",
            "nats://192.168.1.5:4222",
            "nats://[fd7a:115c:a1e0::1]:4222",
            "nats://user:pass@nats.example.com:4222",
        ] {
            let error = check_nats_url(url, false).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("tls://"), "{message}");
            assert!(message.contains(ALLOW_PLAINTEXT_NATS_ENV), "{message}");
            check_nats_url(url, true).unwrap();
        }
    }

    #[test]
    fn missing_or_foreign_schemes_are_rejected() {
        for url in [
            "nats.example.com:4222",
            "",
            "http://nats.example.com:4222",
            "ws://nats.example.com:4222",
            "tls:nats.example.com:4222",
        ] {
            check_nats_url(url, false).unwrap_err();
        }
    }

    #[test]
    fn opt_out_parsing_is_strict() {
        for value in ["1", "true", "yes", "TRUE", " Yes ", "yEs"] {
            assert!(allow_plaintext_nats(Some(value)), "{value}");
        }
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some("2"),
        ] {
            assert!(!allow_plaintext_nats(value), "{value:?}");
        }
    }
}
