# GHAS License Audit Tool

Audit GitHub Advanced Security (GHAS) license usage and track active committers across your organization.

> **⚠️ DISCLAIMER**  
> Community tool - not an official Microsoft/GitHub product. Provided as-is without warranty.

## Features

- **Billing Analysis** - Active committers for Code Security and Secret Protection (90-day window)
- **Audit Logs** - Track GHAS enablement history with actor, timestamp, and method (Enterprise Cloud only)
- **Repository Details** - Metadata, GHAS features status, and commit tracking (optional detailed mode)
- **Comprehensive Reports** - JSON and CSV exports for analysis and compliance

## Requirements

> **⚠️ IMPORTANT**  
> This tool works only with GitHub's **new billing SKU** for Advanced Security, which includes the two new products: **Code Security** and **Secret Protection**.

| Component | PowerShell | Bash |
|-----------|------------|------|
| **GitHub CLI** | ✓ Required | ✓ Required |
| **Permissions** | Org owner or billing manager | Org owner or billing manager |
| **Runtime** | PowerShell 5.1+ or Core 7+ | Bash 4.0+ |
| **Dependencies** | None | `jq` (JSON processor) |

### Installation

**GitHub CLI:**
```bash
# Windows
winget install GitHub.cli

# macOS/Linux
brew install gh

# Authenticate
gh auth login
```

**jq (Bash only):**
```bash
# Ubuntu/Debian
sudo apt-get install jq

# macOS
brew install jq
```

## Usage

### PowerShell

```powershell
# Interactive mode (prompts for inputs)
.\ghas-audit.ps1

# Basic mode
.\ghas-audit.ps1 -Organization "YourOrg"

# Detailed mode (includes metadata, features, commit details)
.\ghas-audit.ps1 -Organization "YourOrg" -DetailedAudit

# Custom output directory
.\ghas-audit.ps1 -Organization "YourOrg" -OutputPath "./reports"
```

### Bash

```bash
# Interactive mode
./ghas-audit.sh

# Basic mode
./ghas-audit.sh -o "YourOrg"

# Detailed mode
./ghas-audit.sh -o "YourOrg" -d

# Custom output directory
./ghas-audit.sh -o "YourOrg" -p "./reports"

# Show help
./ghas-audit.sh -h
```

### Audit Modes

| Mode | Description | API Calls | Reports |
|------|-------------|-----------|---------|
| **Basic** | Essential licensing and committer data | Minimal | 4 files |
| **Detailed** | Full metadata, features, and commit tracking | High | 7 files |

## Output Reports

Each execution creates a timestamped folder: `YourOrg-YYYYMMDD-HHMMSS/`

### Core Reports (Always Generated)

| File | Description |
|------|-------------|
| `summary-report.json` | Organization overview, committer counts, license stats |
| `audit-log.json` | GHAS enablement history (Enterprise Cloud only) |
| `ghas-licensing.csv` | Per-repository licensing: enablement details, committers |
| `active-committers.csv` | Unique committers summary across all repositories |

### Detailed Mode Reports

| File | Description |
|------|-------------|
| `repositories-metadata.csv` | Repo creation, size, language, visibility |
| `repositories-features.csv` | GHAS features status per repository |
| `active-committers-detailed.csv` | Per-repo commit tracking with timestamps and SHAs |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `gh: command not found` | Install GitHub CLI and authenticate with `gh auth login` |
| `jq: command not found` | Install jq: `apt-get install jq` or `brew install jq` |
| Audit log empty | Requires GitHub Enterprise Cloud |
| Permission denied | Verify org owner or billing manager role |
| Rate limit exceeded | Script auto-waits for reset; reduce scope if needed |

## License

MIT License - See [LICENSE](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Report vulnerabilities via [SECURITY.md](SECURITY.md)

---

**Version**: 1.0.0 | **Last Updated**: November 2025
