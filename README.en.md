# dsh-privacy-guard

> A privacy gate for [DeepSeek Harness](https://github.com/deepseek-ai): before the AI reads or writes your personal data, **you** must enter a privacy password in a native Windows window and approve the access. Sensitive values are encrypted and kept on your machine only.

[中文](README.md) · [MIT License](LICENSE)

## What it does

DSH agents can call `read`, `write`, `grep`, `pwsh`, desktop tools, etc. This plugin hooks the tool pipeline:

- **Path layer** (`tools/pre-execute`): a call targeting a protected folder is suspended until you authenticate and approve.
- **Content layer** (`tools/post-execute`): if a tool result contains ID numbers, bank cards, passwords, API keys, etc., it is suspended too; if you reject, the whole result is blocked and never reaches the model.

The password is verified locally. It is **never written into the conversation log and never sent to the model**.

## Features

- Protected folders with `~` and `*` / `**` glob support
- Detectors: Chinese ID card (checksum), bank card (Luhn), phone, email, labeled names, accounts, passwords, API keys, private keys, custom regex
- Native WinForms auth dialog: topmost, countdown, masked summary, remember-for-N-minutes
- Encrypted local vault: scrypt (N=32768) + AES-256-GCM
- Grant TTL (default 10 min), prompt rate limit, exponential lockout after 5 wrong attempts
- Audit log without values
- **No network calls, no telemetry**

## Requirements

- **Windows 10 / 11** (the dialog uses Windows PowerShell 5.1 + WinForms)
- DeepSeek Harness with `dsh` bundle / `cordis` plugin support
- Node.js **>= 22**

## Install

```powershell
# from npm
dsh plugin --profile desktop add dsh-privacy-guard

# from GitHub
dsh plugin --profile desktop add github:KaBanei/dsh-privacy-guard

# from a local clone / tarball
dsh plugin --profile desktop add .\dsh-privacy-guard
dsh plugin --profile desktop add .\dsh-privacy-guard-0.1.0.tgz
```

Restart DSH (or let the profile reload). Then set your password:

```
/privacy setup
```

## Commands

| Command | Description |
| --- | --- |
| `/privacy` / `/privacy status` | Status, protected paths, lock state, 24h allow/deny counts |
| `/privacy setup` | Set / change the privacy password |
| `/privacy unlock` / `lock` | Unlock the vault / wipe in-memory key and grants |
| `/privacy scan` | Collect and encrypt sensitive values now |
| `/privacy vault` | Vault statistics (counts only, never values) |
| `/privacy paths` | List protected paths |
| `/privacy addpath <path>` / `rmpath <path>` | Add / remove a protected path |
| `/privacy on` / `off` | Enable / disable interception |
| `/privacy strict on\|off` | Strict mode (medium-severity matches also require auth) |
| `/privacy audit [n]` | Recent audit entries |
| `/privacy test` | Self-check (crypto, detectors, PowerShell, storage) |

## Data

Everything lives in `~/.dsh/privacy-guard/` (root overridable with `DSH_HOME`):

| File | Content | Encrypted |
| --- | --- | --- |
| `config.json` | paths, switches, timeouts | no (no private data) |
| `secrets.json` | salt, scrypt params, password-wrapped vault key | key wrapped; password not stored |
| `vault.enc` | collected sensitive values | **yes** (AES-256-GCM) |
| `index.json` | type/count/source metadata | no (no raw values) |
| `audit.log` | allow/deny audit | no (no values) |
| `state.json` | failed attempts, lockout | no |

## Threat model

**Stops:** direct reads through tools/shell of protected folders; PII leaking through tool results; offline disk theft of the vault; the AI reading the vault/secrets files.

**Does not stop:** a same-user process with full write access to `~/.dsh` (it can rewrite config or remove the plugin); the unlock window (the vault key lives in host memory while unlocked); PII inside images/screenshots (text detectors cannot see them).

**Privacy:** no network requests, no telemetry, no data leaves the machine. The author cannot decrypt your vault.

## Development

```powershell
node test/selftest.mjs   # 20 checks, no dialogs, temp dir only
```

## License

[MIT](LICENSE)
