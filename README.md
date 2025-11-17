# AD Dangerous ACL Auditor

PowerShell script to identify critical Active Directory security misconfigurations by scanning for dangerous permissions granted to default/well-known groups.

## What it does

Performs a comprehensive scan of your AD domain to find objects where overprivileged groups have dangerous permissions that could lead to privilege escalation or domain compromise.

### Dangerous Groups Monitored
- **Everyone** (S-1-1-0)
- **Authenticated Users** (S-1-5-11)
- **Pre-Windows 2000 Compatible Access** (S-1-5-32-554)
- **Anonymous Logon** (S-1-5-7)
- **BUILTIN\Users** (S-1-5-32-545)

### Dangerous Rights Detected
- **GenericAll** - Full control over object
- **GenericWrite** - Write access to all properties
- **WriteProperty** - Modify object attributes
- **WriteDacl** - Modify permissions (ACL escalation)
- **WriteOwner** - Take ownership of object
- **ExtendedRight** - Special rights including:
  - User-Force-Change-Password
  - DS-Replication-Get-Changes (DCSync)
  - DS-Replication-Get-Changes-All (DCSync)
  - All-Extended-Rights

## Why it matters

These misconfigurations allow:
- **Any authenticated user** to reset passwords, modify group memberships, or take full control of objects
- **Anonymous users** to access or modify AD objects
- **Privilege escalation** through ACL manipulation
- **DCSync attacks** to extract password hashes
- **Lateral movement** through compromised accounts

## Usage
```powershell
.\Find-DangerousACLs.ps1
```

### Output Files
- `DangerousACLs_YYYYMMDD_HHMMSS.csv` - All findings
- `DangerousACLs_CRITICAL_YYYYMMDD_HHMMSS.csv` - Critical findings only (GenericAll, WriteDacl, WriteOwner)

## Features

- ✅ Efficient paging for large domains (tested on 30k+ objects)
- ✅ Real-time progress tracking with color-coded severity
- ✅ Identifies specific Extended Rights (ForceChangePassword, DCSync, etc.)
- ✅ Severity classification (CRITICAL/HIGH/MEDIUM)
- ✅ Inheritance tracking (direct vs inherited permissions)
- ✅ Statistical summary by severity, trustee, and right type
- ✅ No external dependencies (pure ADSI)
- ✅ Timestamped exports for tracking remediation progress

## Requirements

- Domain user account with read access to AD
- PowerShell 5.1 or higher
- No additional modules required (uses built-in ADSI)

## Output Example
```
Starting AD dangerous ACL scan...
Checking for: GenericAll, GenericWrite, WriteProperty, WriteDacl, WriteOwner, ExtendedRight

Processed 1000 objects, checked 998 ACLs, found 3 vulnerable...
FOUND: CN=AdminUser,OU=Users,DC=contoso,DC=com
  → Authenticated Users has GenericAll

========== SCAN SUMMARY ==========
Total objects processed: 25847
Total ACLs checked: 25789
Vulnerable ACEs found: 47

========== BY SEVERITY ==========
CRITICAL: 12
HIGH: 18
MEDIUM: 17

========== BY TRUSTEE ==========
Authenticated Users: 32
Everyone: 10
Pre-Windows 2000 Compatible Access: 5
```

## Severity Levels

| Severity | Rights | Impact |
|----------|--------|--------|
| **CRITICAL** | GenericAll, WriteDacl, WriteOwner | Complete control, ACL manipulation, ownership takeover |
| **HIGH** | ExtendedRight (DCSync, ForceChangePassword) | Password resets, credential theft |
| **MEDIUM** | GenericWrite, WriteProperty | Object modification, potential escalation paths |

## Remediation

1. **Review findings** - Prioritize CRITICAL and HIGH severity items
2. **Remove dangerous permissions** - Use AD Users and Computers or PowerShell
3. **Apply least privilege** - Grant permissions to specific groups, not default groups
4. **Disable Pre-Windows 2000 Compatible Access** if not needed for legacy systems
5. **Re-scan regularly** - Track remediation progress with timestamped exports

### Quick Fix Example
```powershell
# Remove Everyone from object ACL
$obj = [ADSI]"LDAP://CN=User,DC=contoso,DC=com"
$acl = $obj.ObjectSecurity
$everyoneSID = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
$acl.Access | Where-Object { 
    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $everyoneSID.Value 
} | ForEach-Object { $acl.RemoveAccessRule($_) }
$obj.ObjectSecurity = $acl
$obj.CommitChanges()
```

## Common Findings

### Critical Issues
- Default domain GPOs with Everyone/Authenticated Users having GenericAll
- Service accounts with overprivileged permissions
- Legacy objects from old migrations
- Misconfigurations from AD management tools

### False Positives
Some inherited permissions from default AD containers may be expected. Focus on:
- Direct (non-inherited) assignments
- User/computer objects with sensitive data
- High-value targets (admin accounts, service accounts)

## Related Tools

- **BloodHound** - Graph-based AD attack path analysis
- **PingCastle** - Comprehensive AD security assessment
- **Purple Knight** - AD security posture validation

## License

MIT

## Contributing

Pull requests welcome! Areas for improvement:
- Additional dangerous Extended Rights GUIDs
- Object type filtering (focus on high-value targets)
- HTML report generation
- Integration with SIEM/ticketing systems

## Disclaimer

This tool is for authorized security assessments only. Always obtain proper authorization before scanning production environments.
