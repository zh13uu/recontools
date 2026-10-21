<#
.SYNOPSIS
    AD Recon (LDAP/ADSI) - 3 file: Users.csv, Computers.csv, Groups.csv
    Rút gọn, chỉ giữ core recon.

.EXAMPLE
    .\AD-Recon.ps1
    .\AD-Recon.ps1 -OutputDir C:\Audit\Recon
#>

[CmdletBinding()]
param([string]$OutputDir = "")

$ProgressPreference = "SilentlyContinue"
Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue

if (-not $OutputDir) {
    $OutputDir = Join-Path $PWD ("AD-Recon-Results_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# ---------- helpers ----------
function Get-Prop ($Props, $Name) {
    $v = $Props[$Name]; if ($null -eq $v) { return $null }
    if ($v.Count -eq 1) { return $v[0] }
    return ($v -join ';')
}
function Convert-Date ($v) {
    if (-not $v) { return $null }
    try {
        if ($v -is [long]) { return [datetime]::FromFileTime($v) }
        $i = ([long]$v.HighPart -shl 32) + [uint32]$v.LowPart
        if ($i -eq 0 -or $i -gt 1e18) { return $null }
        return [datetime]::FromFileTime($i)
    } catch { return $null }
}
function Convert-Sid ($b) {
    if (-not $b) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier($b,0)).Value } catch { return $null }
}

# ---------- bind ----------
Write-Host "[*] Binding to RootDSE..."
$rootDSE = [ADSI]"LDAP://RootDSE"
$defaultNC = $rootDSE.Properties["defaultNamingContext"][0]
if (-not $defaultNC) { Write-Host "ERROR: Cannot get defaultNamingContext" -ForegroundColor Red; return }
$searchRoot = [ADSI]"LDAP://$defaultNC"
Write-Host "    Domain: $(($defaultNC -replace 'DC=','' -replace ',','.') -replace '^\.','')"

function New-Searcher ([string]$Filter) {
    $s = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
    $s.Filter = $Filter; $s.PageSize = 1000; $s.SizeLimit = 0; $s.CacheResults = $false
    $s
}

# ---------- USERS ----------
Write-Host "[*] Querying Users..."
$Users = @()
$s = New-Searcher "(&(objectCategory=person)(objectClass=user))"
foreach ($r in $s.FindAll()) {
    $p = $r.Properties
    $uac = if ($p.useraccountcontrol) { [int]$p.useraccountcontrol[0] } else { 0 }
    $Users += [PSCustomObject]@{
        SamAccountName        = Get-Prop $p "samaccountname"
        Name                  = Get-Prop $p "name"
        DisplayName           = Get-Prop $p "displayname"
        UserPrincipalName     = Get-Prop $p "userprincipalname"
        DistinguishedName     = Get-Prop $p "distinguishedname"
        Description           = Get-Prop $p "description"
        Email                 = Get-Prop $p "mail"
        Title                 = Get-Prop $p "title"
        Department            = Get-Prop $p "department"
        Company               = Get-Prop $p "company"
        Manager               = Get-Prop $p "manager"
        SID                   = Convert-Sid $p.objectsid
        PrimaryGroupID        = Get-Prop $p "primarygroupid"
        Enabled               = -not (($uac -band 2) -ne 0)
        LockedOut             = ($uac -band 16) -ne 0
        PasswordNeverExpires  = ($uac -band 65536) -ne 0
        PasswordNotRequired   = ($uac -band 32) -ne 0
        PasswordExpired       = ($uac -band 8388608) -ne 0
        TrustedForDelegation  = ($uac -band 524288) -ne 0
        DontRequirePreAuth    = ($uac -band 4194304) -ne 0
        AdminCount            = if ($p.admincount) { [int]$p.admincount[0] } else { 0 }
        UserAccountControl    = $uac
        PasswordLastSet       = Convert-Date (Get-Prop $p "pwdlastset")
        LastLogon             = Convert-Date (Get-Prop $p "lastlogon")
        LastLogonTimestamp    = Convert-Date (Get-Prop $p "lastlogontimestamp")
        LogonCount            = Get-Prop $p "logoncount"
        BadPwdCount           = Get-Prop $p "badpwdcount"
        WhenCreated           = Get-Prop $p "whencreated"
        WhenChanged           = Get-Prop $p "whenchanged"
        MemberOf              = (Get-Prop $p "memberof")
        ServicePrincipalNames = (Get-Prop $p "serviceprincipalname")
    }
}
$s.Dispose()
$Users | Export-Csv -Path (Join-Path $OutputDir "Users.csv") -NoTypeInformation -Encoding UTF8
Write-Host "    -> Users.csv ($($Users.Count))"

# ---------- COMPUTERS ----------
Write-Host "[*] Querying Computers..."
$Computers = @()
$s = New-Searcher "(objectCategory=computer)"
foreach ($r in $s.FindAll()) {
    $p = $r.Properties
    $uac = if ($p.useraccountcontrol) { [int]$p.useraccountcontrol[0] } else { 0 }
    $Computers += [PSCustomObject]@{
        SamAccountName          = Get-Prop $p "samaccountname"
        Name                    = Get-Prop $p "name"
        DNSHostName             = Get-Prop $p "dnshostname"
        DistinguishedName       = Get-Prop $p "distinguishedname"
        OperatingSystem         = Get-Prop $p "operatingsystem"
        OperatingSystemVersion  = Get-Prop $p "operatingsystemversion"
        Enabled                 = -not (($uac -band 2) -ne 0)
        TrustedForDelegation    = ($uac -band 524288) -ne 0
        SID                     = Convert-Sid $p.objectsid
        PrimaryGroupID          = Get-Prop $p "primarygroupid"
        UserAccountControl      = $uac
        Description             = Get-Prop $p "description"
        Location                = Get-Prop $p "location"
        ManagedBy               = Get-Prop $p "managedby"
        LastLogon               = Convert-Date (Get-Prop $p "lastlogon")
        LastLogonTimestamp      = Convert-Date (Get-Prop $p "lastlogontimestamp")
        PasswordLastSet         = Convert-Date (Get-Prop $p "pwdlastset")
        LogonCount              = Get-Prop $p "logoncount"
        BadPwdCount             = Get-Prop $p "badpwdcount"
        WhenCreated             = Get-Prop $p "whencreated"
        WhenChanged             = Get-Prop $p "whenchanged"
        ServicePrincipalNames   = (Get-Prop $p "serviceprincipalname")
        MemberOf                = (Get-Prop $p "memberof")
    }
}
$s.Dispose()
$Computers | Export-Csv -Path (Join-Path $OutputDir "Computers.csv") -NoTypeInformation -Encoding UTF8
Write-Host "    -> Computers.csv ($($Computers.Count))"

# ---------- GROUPS ----------
Write-Host "[*] Querying Groups..."
$Groups = @()
$s = New-Searcher "(objectCategory=group)"
foreach ($r in $s.FindAll()) {
    $p = $r.Properties
    $gtype = if ($p.grouptype) { [int]$p.grouptype[0] } else { 0 }
    $scope = if ($gtype -band -2147483648) { "Global" }
             elseif ($gtype -band -1073741824) { "Universal" }
             elseif ($gtype -band 0x80000000)  { "DomainLocal" }
             else { "Unknown" }
    $category = if ($gtype -band 0x80000000) { "Security" } else { "Distribution" }
    $members = $p.member
    $Groups += [PSCustomObject]@{
        SamAccountName    = Get-Prop $p "samaccountname"
        Name              = Get-Prop $p "name"
        DistinguishedName = Get-Prop $p "distinguishedname"
        GroupCategory     = $category
        GroupScope        = $scope
        Description       = Get-Prop $p "description"
        MemberCount       = if ($members) { @($members).Count } else { 0 }
        AdminCount        = if ($p.admincount) { [int]$p.admincount[0] } else { 0 }
        ManagedBy         = Get-Prop $p "managedby"
        SID               = Convert-Sid $p.objectsid
        WhenCreated       = Get-Prop $p "whencreated"
        WhenChanged       = Get-Prop $p "whenchanged"
        Members           = (Get-Prop $p "member")
        MemberOf          = (Get-Prop $p "memberof")
        Mail              = Get-Prop $p "mail"
    }
}
$s.Dispose()
$Groups | Export-Csv -Path (Join-Path $OutputDir "Groups.csv") -NoTypeInformation -Encoding UTF8
Write-Host "    -> Groups.csv ($($Groups.Count))"

Write-Host ""
Write-Host "DONE -> $OutputDir" -ForegroundColor Green
