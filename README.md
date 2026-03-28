# AgentArmor

Security scanner for AI agents. Scans your agent installation, checks it against the official security documentation, and gives you a score out of 100.

Currently supports **OpenClaw**. Pluggable architecture makes it easy to add more agent types.

## Quick Start

```bash
npm install
npm run build
node dist/index.js scan
```

## Usage

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

## Scoring

Each check has a severity level (critical, high, medium, low) and a point value. Your total score is the sum of earned points out of 100.

- **80-100**: Well hardened
- **60-79**: Needs attention
- **Below 60**: Significant risks

## Example Output

```
  AgentArmor Security Scan — OpenClaw
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Score: 72/100

  Authentication                     8/12
    ✓ Gateway auth enabled                 4/4
    ✓ Token auth mode (recommended)        4/4
    ✗ Auth token strength                  0/4
      Token length: 13 chars (minimum 32 recommended)
      Fix: Generate a strong token: openclaw doctor --generate-gateway-token

  File Permissions                   10/10
    ✓ ~/.openclaw directory permissions    4/4
    ✓ Config file permissions              3/3
    ✓ Credential file permissions          3/3

  ...

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 critical, 0 failed, 3 warnings
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Scan passed (no critical failures) |
| 1 | Critical security issues found |
| 2 | Scanner error (agent not found, config parse failure, etc.) |

## Adding a New Agent

Create a new directory under `src/agents/<name>/` and implement the `AgentPlugin` interface:

```typescript
interface AgentPlugin {
  name: string;
  displayName: string;
  detect(): Promise<boolean>;
  scan(): Promise<CheckResult[]>;
}
```

Then register it in `src/agents/index.ts`. See `src/agents/openclaw/` for a complete example.

## Tech Stack

- TypeScript (strict mode)
- Node.js 18+
- [commander](https://github.com/tj/commander.js) — CLI framework
- [chalk](https://github.com/chalk/chalk) — Terminal colors
- [json5](https://github.com/json5/json5) — Parse OpenClaw config (supports comments/trailing commas)
- [tsup](https://github.com/egoist/tsup) — Bundler

## Development

```bash
npm install
npm run dev    # Watch mode
npm run build  # Production build
```

## License

MIT
