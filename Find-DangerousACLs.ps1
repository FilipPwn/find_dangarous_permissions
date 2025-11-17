$searcher = [ADSISearcher]""
$searcher.Filter = "(objectClass=*)"
$searcher.PageSize = 1000
$searcher.SearchScope = "Subtree"
$searcher.PropertiesToLoad.AddRange(@("distinguishedName", "nTSecurityDescriptor", "objectClass"))

# Well-known SIDs
$dangerousGroups = @{
    "S-1-1-0" = "Everyone"
    "S-1-5-11" = "Authenticated Users"
    "S-1-5-32-554" = "Pre-Windows 2000 Compatible Access"
    "S-1-5-7" = "Anonymous Logon"
    "S-1-5-32-545" = "BUILTIN\Users"
}

# Dangerous rights to check for
$dangerousRights = @(
    "GenericAll",
    "GenericWrite", 
    "WriteProperty",
    "WriteDacl",
    "WriteOwner",
    "ExtendedRight"  # Includes ForceChangePassword, DCSync rights, etc.
)

$results = @()
$count = 0
$aclCount = 0

Write-Host "Starting AD dangerous ACL scan..." -ForegroundColor Green
Write-Host "Checking for: $($dangerousRights -join ', ')`n" -ForegroundColor Cyan

$searcher.FindAll() | ForEach-Object {
    $count++
    if ($count % 1000 -eq 0) {
        Write-Host "Processed $count objects, checked $aclCount ACLs, found $($results.Count) vulnerable..." -ForegroundColor Yellow
    }
    
    $dn = $_.Properties["distinguishedname"][0]
    $obj = $_.GetDirectoryEntry()
    
    try {
        $acl = $obj.ObjectSecurity
        $aclCount++
        
        foreach ($ace in $acl.Access) {
            try {
                $aceSID = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                
                if ($dangerousGroups.ContainsKey($aceSID) -and $ace.AccessControlType -eq "Allow") {
                    
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    $objectType = $ace.ObjectType.ToString()
                    
                    # Check for any dangerous right
                    $matchedRights = $dangerousRights | Where-Object { $rights -match $_ }
                    
                    if ($matchedRights) {
                        # Special handling for ExtendedRight to identify specific rights
                        $extendedRightName = ""
                        if ($rights -match "ExtendedRight") {
                            # Well-known Extended Rights GUIDs
                            $extendedRights = @{
                                "00299570-246d-11d0-a768-00aa006e0529" = "User-Force-Change-Password"
                                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
                                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
                                "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
                                "00000000-0000-0000-0000-000000000000" = "All-Extended-Rights"
                            }
                            
                            if ($extendedRights.ContainsKey($objectType)) {
                                $extendedRightName = $extendedRights[$objectType]
                            } else {
                                $extendedRightName = $objectType
                            }
                        }
                        
                        $result = [PSCustomObject]@{
                            DistinguishedName = $dn
                            ObjectClass = $_.Properties["objectclass"][-1]
                            Rights = $rights
                            ExtendedRight = $extendedRightName
                            Trustee = $dangerousGroups[$aceSID]
                            TrusteeSID = $aceSID
                            InheritanceType = $ace.InheritanceType
                            IsInherited = $ace.IsInherited
                        }
                        
                        $results += $result
                        
                        $color = switch -Wildcard ($rights) {
                            "*GenericAll*" { "Red" }
                            "*WriteDacl*" { "Red" }
                            "*WriteOwner*" { "Red" }
                            "*ExtendedRight*" { "Magenta" }
                            default { "Yellow" }
                        }
                        
                        Write-Host "FOUND: $dn" -ForegroundColor $color
                        Write-Host "  → $($dangerousGroups[$aceSID]) has $rights $(if($extendedRightName){"[$extendedRightName]"})" -ForegroundColor $color
                    }
                }
            } catch {
                # Skip SID translation errors
            }
        }
    } catch {
        # Skip objects without accessible ACLs
    }
}

Write-Host "`n========== SCAN SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Total objects processed: $count" -ForegroundColor Green
Write-Host "Total ACLs checked: $aclCount" -ForegroundColor Cyan
Write-Host "Vulnerable ACEs found: $($results.Count)" -ForegroundColor Red

# Group by severity
Write-Host "`n========== BY SEVERITY ==========" -ForegroundColor Cyan
$results | Group-Object { 
    if ($_.Rights -match "GenericAll|WriteDacl|WriteOwner") { "CRITICAL" }
    elseif ($_.Rights -match "ExtendedRight") { "HIGH" }
    else { "MEDIUM" }
} | Sort-Object Name -Descending | ForEach-Object {
    $color = switch ($_.Name) {
        "CRITICAL" { "Red" }
        "HIGH" { "Magenta" }
        "MEDIUM" { "Yellow" }
    }
    Write-Host "$($_.Name): $($_.Count)" -ForegroundColor $color
}

# Group by trustee
Write-Host "`n========== BY TRUSTEE ==========" -ForegroundColor Cyan
$results | Group-Object Trustee | Sort-Object Count -Descending | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count)" -ForegroundColor Yellow
}

# Group by right type
Write-Host "`n========== BY RIGHT TYPE ==========" -ForegroundColor Cyan
$results | Group-Object Rights | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count)" -ForegroundColor White
}

$results | Format-Table -AutoSize

# Export results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = "DangerousACLs_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nResults exported to: $csvPath" -ForegroundColor Green

# Export critical findings only
$critical = $results | Where-Object { $_.Rights -match "GenericAll|WriteDacl|WriteOwner" }
if ($critical) {
    $criticalPath = "DangerousACLs_CRITICAL_$timestamp.csv"
    $critical | Export-Csv -Path $criticalPath -NoTypeInformation
    Write-Host "Critical findings exported to: $criticalPath" -ForegroundColor Red
}
