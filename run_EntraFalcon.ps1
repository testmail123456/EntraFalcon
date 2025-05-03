<#
    .Synopsis
    PowerShell-based security assessment tool for Microsoft Entra ID environments.

    .Description
    EntraFalcon is a PowerShell-based assessment tool for pentesters, security analysts, and system administrators to evaluate the security posture of a Microsoft Entra ID environment.
    The tool identifies potential privilege escalation paths, excessive permissions, inactive accounts, and Conditional Access misconfigurations across users, groups, applications, roles, and policies. Findings are compiled into interactive HTML reports with a simple risk scoring.
    Designed with a focus on ease of use, EntraFalcon runs on PowerShell 5.1 and 7, supports both Windows and Linux, and requires no external dependencies or Microsoft Graph API consent.

    .PARAMETER Tenant
    Specifies the Entra ID tenant to authenticate against.
    Use this to target a specific tenant ID or domain, especially when enumerating tenants other than the account’s home tenant.
    - `organizations` (for multi-tenant apps)
    - A specific tenant ID
    Default: `organizations`

    .PARAMETER UserAgent
    Specifies the user agent string to be used in the HTTP requests to the token endpoint and APIs
    Default: `EntraFalcon`

    .PARAMETER DisableCAE
    Disables Continuous Access Evaluation (CAE), resulting in shorter-lived access tokens.
    Useful when CAE breaks the script.

    .PARAMETER AuthMethod
    3 different Authentication methods are supported:
    - `AuthCode` (default): Interactive browser login using legacy .NET
    - `DeviceCode`: Device Code Flow for environments without a browser
    - `ManualCode`: Outputs an auth URL for use on a separate device, and requires manual input of the authorization code
    
    .PARAMETER SkipPimForGroups
    Skips the enumeration of PIM for Groups, avoiding the need for a secondary authentication flow.

    .PARAMETER IncludeMsApps
    Includes Microsoft-owned enterprise applications in the enumeration and analysis.  
    By default, these are excluded to reduce noise.

    .NOTES
    Author: Christian Feuchter, Compass Security Switzerland AG, https://www.compass-security.com/
    Source: https://github.com/CompassSecurity/EntraFalcon 

#>



[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("AuthCode", "DeviceCode", "ManualCode")]
    [string]$AuthMethod = "AuthCode",

    [Parameter(Mandatory = $false)]
    [string]$UserAgent = "EntraFalcon",

    [Parameter(Mandatory = $false)]
    [switch]$SkipPimForGroups = $false,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeMsApps = $false,

    [Parameter(Mandatory=$false)]
    [switch]$DisableCAE = $false,

    [Parameter(Mandatory=$false)]
    [string]$Tenant,

    [Parameter(Mandatory = $false)]
    [string]$OutputFolder,

    [Parameter(Mandatory = $false)]
    [switch]$ManualCode #Alias because of EntraTokenAid error message
)
# Override AuthMethod if -ManualCode is used
if ($ManualCode.IsPresent) {
    $AuthMethod = "ManualCode"
}

#Constants
$EntraFalconVersion = "V20250505"

#Define additional authentication parameters
$Global:GLOBALAuthParameters = @{}
$GLOBALAuthParameters['UserAgent'] = $UserAgent
if ($DisableCAE) {
    $GLOBALAuthParameters['DisableCAE'] = $true
}
if ($null -ne $Tenant -and "" -ne $Tenant) {
    $GLOBALAuthParameters['Tenant'] = $Tenant
}

# Optional parameters for the sub-modules
$optionalParams = @{}
if ($IncludeMsApps) {
    $optionalParams['IncludeMsApps'] = $true
}

# Import shared functions
import-module ./modules/shared_Functions.psm1 -force
import-module ./modules/check_Groups.psm1 -force
import-module ./modules/check_EnterpriseApps.psm1 -force
import-module ./modules/check_AppRegistrations.psm1 -force
import-module ./modules/check_Users.psm1 -force
import-module ./modules/check_ManagedIdentities.psm1 -force
import-module ./modules/check_Roles.psm1 -force
import-module ./modules/check_CAPs.psm1 -force
import-module ./modules/Send-GraphBatchRequest.psm1 -force
import-module ./modules/Send-GraphRequest.psm1 -force
import-module ./modules/export_Summary.psm1 -force

#Define summary array and show banner
Start-InitTasks -EntraFalconVersion $EntraFalconVersion -UserAgent $UserAgent
Show-EntraFalconBanner -EntraFalconVersion $EntraFalconVersion



if (-not($SkipPimForGroups)) {
write-host ""
write-host "********************************** PIM for Groups: Pre-Collection Phase **********************************"
    $TenantPimForGroupsAssignments = Get-PimforGroupsAssignments -AuthMethod $AuthMethod
} else {
    $global:GLOBALPimForGroupsChecked = $false
}


write-host ""
write-host "********************************** Main Authentication **********************************"
# Perform authentication check and authenticate if required
if (-Not(EnsureAuthMsGraph -AuthMethod $AuthMethod)) {
    Return
}

write-host ""
write-host "********************************** Gather Basic Data **********************************"
# Gather basic data
$CurrentTenant = Get-OrgInfo
$StartTimestamp = Get-Date -Format "yyyyMMdd_HHmm"
$GlobalAuditSummary.Tenant.Name = $CurrentTenant.DisplayName
$GlobalAuditSummary.Tenant.Id = $CurrentTenant.Id

#Define output folder if not defined
if ($null -eq $OutputFolder -or "" -eq $OutputFolder) {
    $OutputFolder = "Results_$($CurrentTenant.DisplayName)_$($StartTimestamp)"
}
# Create report directory
if (-not (Test-Path -Path $OutputFolder)) {
    try {
        New-Item -ItemType Directory -Path $OutputFolder -ErrorAction Stop | out-null
    } catch {
        Write-Host "[!] Failed to create folder '$OutputFolder': $($_.Exception.Message)"
        Write-Host "[!] Aborting..."
        Start-CleanUp
        exit 1
    }
}

$AdminUnitWithMembers = Get-AdministrativeUnitsWithMembers
$Caps = Get-ConditionalAccessPolicies
# Get PIM eligible role assignments
if (Invoke-MsGraphAuthPIM) {
    $TenantPimRoleAssignments = Get-EntraPIMRoleAssignments
}
#Get active role assignments and merge eligible
$TenantRoleAssignments = Get-EntraRoleAssignments -TenantPimRoleAssignments $TenantPimRoleAssignments

# Check if authentication to Azure ARM API works and if the user has access to a subscription
if ((EnsureAuthAzurePsNative) -and (checkSubscriptionNative)){
    $global:GLOBALAzurePsChecks = $true
    $AzureIAMAssignments = Get-AllAzureIAMAssignmentsNative
} else {
    $global:GLOBALAzurePsChecks = $false
    Write-Host "[!] No AzurePS session: No Azure IAM assignments will be checked"
    $AzureIAMAssignments = @{}
}


if ($TenantPimForGroupsAssignments) {
    Write-Host "[*] Post processing PIM for Groups results..."
    $TenantPimForGroupsAssignments = Get-PIMForGroupsAssignmentsDetails -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments
}

# Get user's MFA status
$UserAuthMethodsTable = Get-RegisterAuthMethodsUsers


write-host "`n********************************** Enumerating Groups **********************************"
$AllGroupsDetails = Invoke-CheckGroups -AdminUnitWithMembers $AdminUnitWithMembers -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -ConditionalAccessPolicies $Caps -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments -OutputFolder $OutputFolder -Verbose:$VerbosePreference

write-host "`n********************************** Enumerating Enterprise Apps **********************************"
$EnterpriseApps = Invoke-CheckEnterpriseApps -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -OutputFolder $OutputFolder -Verbose:$VerbosePreference @optionalParams

write-host "`n********************************** Enumerating Managed Identities **********************************"
$ManagedIdentities = Invoke-CheckManagedIdentities -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AllGroupsDetails $AllGroupsDetails -OutputFolder $OutputFolder -Verbose:$VerbosePreference

write-host "`n********************************** Enumerating App Registrations **********************************"
$AppRegistrations = Invoke-CheckAppRegistrations -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -TenantRoleAssignments $TenantRoleAssignments -OutputFolder $OutputFolder -Verbose:$VerbosePreference

write-host "`n********************************** Enumerating Users **********************************"
$Users = Invoke-CheckUsers -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -ConditionalAccessPolicies $Caps -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AppRegistrations $AppRegistrations -AdminUnitWithMembers $AdminUnitWithMembers -TenantPimForGroupsAssignments $TenantPimForGroupsAssignments -UserAuthMethodsTable $UserAuthMethodsTable -OutputFolder $OutputFolder -Verbose:$VerbosePreference

write-host "`n********************************** Generating Role Assignments **********************************"
Invoke-CheckRoles -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -EnterpriseApps $EnterpriseApps -AllGroupsDetails $AllGroupsDetails -AzureIAMAssignments $AzureIAMAssignments -TenantRoleAssignments $TenantRoleAssignments -AppRegistrations $AppRegistrations -AdminUnitWithMembers $AdminUnitWithMembers -Users $Users -ManagedIdentities $ManagedIdentities -OutputFolder $OutputFolder -Verbose:$VerbosePreference

write-host "`n********************************** Generating CAP Report **********************************"
Invoke-CheckCaps -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -AllGroupsDetails $AllGroupsDetails -Users $Users -OutputFolder $OutputFolder -TenantRoleAssignments $TenantRoleAssignments -Verbose:$VerbosePreference

# Show assessment summary and generate summary HTML report
Export-Summary -CurrentTenant $CurrentTenant -StartTimestamp $StartTimestamp -OutputFolder $OutputFolder -Verbose:$VerbosePreference

# Remove global variables
Start-CleanUp

