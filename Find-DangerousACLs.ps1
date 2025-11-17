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
}

$results = @()
$count = 0
$aclCount = 0

Write-Host "Starting search..." -ForegroundColor Green

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
                    
                    if ($rights -match "GenericAll") {
                        $results += [PSCustomObject]@{
                            DistinguishedName = $dn
                            ObjectClass = $_.Properties["objectclass"][-1]
                            Rights = $rights
                            Trustee = $dangerousGroups[$aceSID]
                            TrusteeSID = $aceSID
                            InheritanceType = $ace.InheritanceType
                        }
                        Write-Host "FOUND: $dn - $($dangerousGroups[$aceSID]) - $rights" -ForegroundColor Red
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

Write-Host "`nTotal objects processed: $count" -ForegroundColor Green
Write-Host "Total ACLs checked: $aclCount" -ForegroundColor Cyan
Write-Host "Vulnerable objects found: $($results.Count)" -ForegroundColor Red

$results | Format-Table -AutoSize
$results | Export-Csv -Path "GenericAll_DangerousGroups.csv" -NoTypeInformation
