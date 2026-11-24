# AgentArmor

Security scanner for AI agents. Scans your agent installation, checks it against the official security documentation, and gives you a score out of 100.

Currently supports **OpenClaw**. Pluggable architecture makes it easy to add more agent types.

Built in Rust — ships as a single self-contained binary. No runtime required.

## Installation

**From source:**
```bash
cargo build --release
cp target/release/agent-armor /usr/local/bin/
```

**Via cargo:**
```bash
cargo install agent-armor
```

**Homebrew** (coming soon):
```bash
brew install agent-armor
```

## Usage

[How to check your OpenClaw setup with AgentArmor](https://www.zenopensource.org/guides/agentarmor) walks through a local scan, a file-permissions finding, and the second scan that verifies the fix.

```bash
# Auto-detect installed agent and scan
agent-armor scan

# Specify agent type
agent-armor scan --agent openclaw

# Show all checks (including passing)
agent-armor scan --verbose

# Machine-readable JSON output
agent-armor scan --json
```

## What It Checks

AgentArmor runs 30 security checks across 14 categories, all derived from the [OpenClaw Security Documentation](https://docs.openclaw.ai/gateway/security):

| Category | Points | Checks |
|---|---|---|
| Authentication | 12 | Auth mode, token vs password, token strength (>= 32 chars) |
| File Permissions | 10 | `~/.openclaw` dir is 700, config is 600, credential files protected |
| Network Exposure | 12 | Loopback binding, port not publicly exposed, Tailscale preferred |
| DM Security | 8 | DM policy is pairing/allowlist, per-channel-peer session isolation |
| Group Security | 6 | Groups require @mention, no open group policies |
| Tool Authorization | 10 | Dangerous tools denied, elevated tools disabled, restrictive profile |
| Exec Security | 10 | Shell exec denied, approval required, strict inline eval |
| Sandboxing | 10 | Sandbox mode enabled, per-agent/session scope, no dangerous Docker flags |
| Browser Security | 6 | SSRF private network blocked, dedicated browser profile |
| Dangerous Flags | 6 | No insecure config flags enabled |
| Logging & Privacy | 4 | Sensitive data redaction, transcript permissions |
| mDNS/Discovery | 2 | mDNS set to minimal or off |
| Control UI | 2 | Origin allowlist configured, device auth enabled |
| Plugins | 2 | Explicit plugin allowlist configured |
| Secrets Management | 12 | secrets.json permissions, auth profile permissions, no hardcoded passwords, no plaintext API keys, secrets not in agent workspace |

## Scoring

Each check has a severity level (critical, high, medium, low) and a point value. Your score is normalized to 100 regardless of how many checks are active.

- **80–100**: Well hardened
- **60–79**: Needs attention
- **Below 60**: Significant risks

## Example Output

```
  AgentArmor Security Scan — OpenClaw
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Score: 72/100 (81/112 pts)

  Authentication                     8/12
    ✓ Gateway auth enabled                 4/4
    ✓ Token auth mode (recommended)        4/4
    ✗ Auth token strength                  0/4
      Token length: 13 chars (minimum 32 recommended)
      Fix: Generate a strong token: openclaw doctor --generate-gateway-token

  Secrets Management                 9/12
    ✓ secrets.json permissions             2/2
    ✓ Auth profile file permissions        2/2
    ✓ Password not hardcoded in config     3/3
    ✓ No plaintext secrets in config       3/3
    ⚠ Secrets not in agent workspace       0/2
      ...
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Scan passed (no critical failures) |
| 1 | Critical security issues found |
| 2 | Scanner error (agent not found, config parse failure, etc.) |

## Adding a New Agent

Create a new module under `src/agents/<name>/` and implement the `AgentPlugin` trait:

```rust
pub trait AgentPlugin {
    fn name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn detect(&self) -> bool;
    fn scan(&self) -> anyhow::Result<Vec<CheckResult>>;
}
```

Then register it in `src/agents/mod.rs`. See `src/agents/openclaw/` for a complete example.

## Building

Requires Rust 1.70+.

```bash
cargo build            # Debug build
cargo build --release  # Optimized release build (stripped, LTO enabled)
```

## License

MIT
