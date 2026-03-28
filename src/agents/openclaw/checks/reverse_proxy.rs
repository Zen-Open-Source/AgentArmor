use serde_json::Value;
use std::path::Path;
use crate::types::{CheckResult, CheckStatus, Severity};
use crate::utils::config::{get, get_bool, get_str};

pub fn check(config: &Value, _base: &Path) -> Vec<CheckResult> {
    let bind = get_str(config, "gateway.bind");
    let is_loopback = bind.is_none() || bind == Some("loopback");

    if is_loopback {
        return vec![];
    }

    let trusted_proxies = get(config, "gateway.trustedProxies").and_then(|v| v.as_array());
    let allow_fallback = get_bool(config, "gateway.allowRealIpFallback");
    let properly_configured = trusted_proxies.is_some() && allow_fallback == Some(false);

    vec![CheckResult {
        id: "reverse-proxy-config",
        name: "Reverse proxy configured safely",
        category: "Reverse Proxy",
        severity: Severity::High,
        points: 0,
        earned: 0,
        status: if properly_configured { CheckStatus::Pass } else { CheckStatus::Warn },
        message: if properly_configured {
            "Trusted proxies configured and real IP fallback disabled".into()
        } else {
            "When using a reverse proxy, set gateway.trustedProxies and disable allowRealIpFallback".into()
        },
        fix: Some("Set gateway.trustedProxies to proxy IPs and gateway.allowRealIpFallback to false"),
    }]
}
