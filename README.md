# AD Dangerous ACL Auditor

Quick PowerShell script to identify Active Directory objects with overprivileged permissions granted to default/well-known groups.

## What it does

Scans your entire AD domain to find objects where these groups have GenericAll rights:
- **Everyone** (S-1-1-0)
- **Authenticated Users** (S-1-5-11)  
- **Pre-Windows 2000 Compatible Access** (S-1-5-32-554)

## Why it matters

These permissions allow any user (or in some cases, anonymous users) to fully control AD objects - a critical security misconfiguration that can lead to privilege escalation and domain compromise.

## Usage
```powershell
.\Find-DangerousACLs.ps1
```

Results are exported to `GenericAll_DangerousGroups.csv`

## Requirements

- Domain user account (read access to AD)
- PowerShell 5.1+
- RSAT-AD-PowerShell (optional, uses ADSI)

## Features

- Efficient paging for large domains (30k+ objects)
- Real-time progress tracking
- CSV export for further analysis
- No external dependencies

## Output

| DistinguishedName | ObjectClass | Rights | Trustee | TrusteeSID | InheritanceType |
|-------------------|-------------|--------|---------|------------|-----------------|
| CN=User,DC=domain | user | GenericAll | Everyone | S-1-1-0 | None |

## License

MIT
