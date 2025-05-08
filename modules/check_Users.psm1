<#
	.SYNOPSIS
	   Enumerates and analyzes all users in the current tenant, including access, ownerships, roles, and risk posture.

	.DESCRIPTION
		This script will enumerate all users including:
		 - User Type
		 - Status
		 - Onprem
		 - Groups assigned
		 - Owner of Groups
		 - AuUnits
		 - Roles (only active assignments)
		 - Application / SP ownership
		 - Device Owner / Registered devices
		 - Last sign-in

#>
function Invoke-CheckUsers {
    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][switch]$SkipAutoRefresh = $false,
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][Object[]]$ConditionalAccessPolicies,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$true)][hashtable]$AllGroupsDetails,
        [Parameter(Mandatory=$true)][hashtable]$EnterpriseApps,
        [Parameter(Mandatory=$false)][hashtable]$UserAuthMethodsTable,
        [Parameter(Mandatory=$true)][hashtable]$AppRegistrations,
        [Parameter(Mandatory=$false)][Object[]]$TenantPimForGroupsAssignments
    )


    ############################## Function section ########################


    ############################## Script section ########################
    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    #Define basic variables
    $Title = "Users"
    $ProgressCounter = 0
    $TokenCheckLimit = 5000  # Define recheck limit for token lifetime. In large environments the access token might expire during the test.
    $DetailOutputTxt = ""
    $PermissionUserSignInActivity = $true
    $AllUsersDetails = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $WarningReport = @()
    if (-not $GLOBALGraphExtendedChecks) {$WarningReport += "Only active role assignments assessed!"}
    if (-not ($GLOBALPimForGroupsChecked)) {$WarningReport += "Pim for Groups was not assessed!"}
    if (-not ($GLOBALAzurePsChecks)) {$WarningReport += "Users Azure IAM assignments were not assessed!"}
    $UserImpact = @{
    "Base"                      = 1
    "DirectAppRoleNormal"       = 10
    "DirectAppRoleSensitive"    = 50
    "SpOwnAppLock"              = 20
    }
	
    $UserLikelihood = @{
	"Base"                      = 5
	"SyncedFromOnPrem"          = 3
    "Protected"                 = -4
    "NoMFA"                     = 10
    }

    # List of roles which members are not protected against the password reset of other low-tier admin roles.
    # Reference: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions?tabs=admin-center#who-can-reset-passwords
    $UnprotectedRoles = @(
        'Auth Admin',
        'Directory Readers',
        'Groups Admin',
        'Guest Inviter',
        'Helpdesk Admin',
        'Message Center Reader',
        'Password Admin',
        'Reports Reader',
        'User Admin',
        'User Experience Success Manager',
        'Usage Summary Reports Reader'
    )

    if ($TenantPimForGroupsAssignments) {

        # Initialize an empty hashtable
        $UserGroupMapping = @{}

        # Iterate through each object in the list
        $TenantPimForGroupsAssignments | Where-Object { $_.Type -eq "User" } | ForEach-Object {
            $principalId = $_.principalId
            $groupId = $_.groupId
            $accessId = $_.accessId

            # Create an object with groupId and accessId
            $entry = [PSCustomObject]@{
                groupId  = $groupId
                accessId = $accessId
            }

            # If the principalId already exists in the hashtable, append to the array
            if ($UserGroupMapping.ContainsKey($principalId)) {
                $UserGroupMapping[$principalId] += $entry
            } else {
                # Otherwise, create a new array with the first object
                $UserGroupMapping[$principalId] = @($entry)
            }
        }

    }

    ########################################## SECTION: DATACOLLECTION ##########################################


    # Checking if users SignInActivity property can be retrieved. Requires Premium otherwise HTTP 403:Tenant is not a B2C tenant and doesn't have premium license
    $QueryParameters = @{
        '$select' = "SignInActivity"
    }
    try {
        Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name) -ErrorAction Stop | out-null
    } catch {
        if ($($_.Exception.Message) -match "Status: 403") {
            write-host "[!] HTTP 403 Error: Most likely due to missing Entra ID premium licence. Can't retrieve SignInActivity."
        } else {
            write-host "[!] Auth error: $($_.Exception.Message -split '\n'). Can't retrieve SignInActivity."
        }
        $WarningReport = "No permissions to retrieve users SignInActivity properties. Inactive users are not marked."
        $PermissionUserSignInActivity = $false
    }


    #Perform collection
    write-host "[*] Get all users"
    if ($PermissionUserSignInActivity) {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,BusinessPhones,AssignedLicenses,OtherMails,OnPremisesSyncEnabled,OnPremisesExtensionAttributes,Authentication,AuthorizationInfo,SignInActivity,CreatedDateTime,JobTitle,Department"
        }
    } else {
        $QueryParameters = @{
            '$select' = "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,BusinessPhones,AssignedLicenses,OtherMails,OnPremisesSyncEnabled,OnPremisesExtensionAttributes,Authentication,AuthorizationInfo,CreatedDateTime,JobTitle,Department"
        } 
    }
    $AllUsers = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri "/users" -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $UsersTotalCount = @($AllUsers).count
    write-host "[+] Got $($UsersTotalCount) users"


    Write-Host "[*] Get all users memberships"
    #Get all users memberships  for later lookup
    $Requests = @()
    $AllUsers | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/users/$($_.id)/transitiveMemberOf"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $UserMemberOfRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $UserMemberOfRaw[$item.id] = $item.response.value
        }
    }

    # Count transitive memberships
    $TotalTransitiveMemberRelations = 0
    foreach ($members in $UserMemberOfRaw.Values) {
        $TotalTransitiveMemberRelations += $members.Count
    }

    Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Got transitive member relationships: $TotalTransitiveMemberRelations"
    

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all users ownerships"
    #Get all users ownerships for later lookup
    $Requests = @()
    $AllUsers | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/users/$($_.id)/ownedObjects"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $UserOwnedObjectsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $UserOwnedObjectsRaw[$item.id] = $item.response.value
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all users device ownerships"
    #Get all users device ownerships for later lookup
    $Requests = @()
    $AllUsers | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/users/$($_.id)/ownedDevices"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $DeviceOwnerRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $DeviceOwnerRaw[$item.id] = $item.response.value
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all users device registrations"
    #Get all users device registrations for later lookup
    $Requests = @()
    $AllUsers | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    = "/users/$($_.id)/registeredDevices"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $DeviceRegisteredRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $DeviceRegisteredRaw[$item.id] = $item.response.value
        }
    }    

    ########################################## SECTION: User Processing ##########################################

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($UsersTotalCount / 10), 1)
    Write-Host "[*] Status: Processing user 1 of $UsersTotalCount (updates every $StatusUpdateInterval users)..."

    #Loop through all users and get additional info and store it in a custom object
    foreach ($item in $AllUsers) {

        # Clean vars
        $Warnings = @()
        $Protected = $false
        $ProgressCounter ++
        $Impact = $UserImpact["Base"]
        $Likelihood = $UserLikelihood["Base"]
        $LastInteractiveSignIn = $item.SignInActivity.LastSignInDateTime
        $LastNonInteractiveSignIn = $item.SignInActivity.LastNonInteractiveSignInDateTime
        $LastSuccessfulSignInTime = $item.SignInActivity.lastSuccessfulSignInDateTime
        $CreatedDays = (New-TimeSpan -Start $item.CreatedDateTime).Days
        $EntraRolesTroughGroupOwnership = 0
        $EntraRolesTroughGroupMembership = 0
        $AzureRolesTroughGroupOwnership = 0
        $AzureRolesTroughGroupMembership = 0
        $Inactive = $false
        $UserEntraRoles = @()
        
        # Check the token lifetime after a specific amount of objects
        if (($ProgressCounter % $TokenCheckLimit) -eq 0 -and $SkipAutoRefresh -eq $false) {
            if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
        }

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $UsersTotalCount) {
            Write-Host "[*] Status: Processing user $ProgressCounter of $UsersTotalCount..."
        }

        if(($item.AssignedLicenses).Count -ne 0) {
            $LicenseStatus = "Licensed"
        }
        else {
            $LicenseStatus = "Unlicensed"
        }

        if ($item.OnPremisesSyncEnabled) {
            $OnPrem = $true
            $Likelihood += $UserLikelihood["SyncedFromOnPrem"]
        } else {
            $OnPrem = $false
        }


        #Get users memberships (ignoring directory roles)
        $UserMemberGroups   = [System.Collections.ArrayList]::new()
		$AUMember   	    = [System.Collections.ArrayList]::new()
        if ($UserMemberOfRaw.ContainsKey($item.Id)) {
            foreach ($member in $UserMemberOfRaw[$item.Id]) {
                switch ($member.'@odata.type') {
        
                    '#microsoft.graph.group' {
                        [void]$UserMemberGroups.Add(
                            [PSCustomObject]@{
                                Id             = $member.Id
                                AssignmentType = 'Active'
                            }
                        )
                    }
                    '#microsoft.graph.administrativeUnit' {
                        [void]$AUMember.Add(
                            [PSCustomObject]@{
                                Id                           = $member.Id
                                displayName                  = $member.displayName
                                isMemberManagementRestricted = $member.isMemberManagementRestricted
                            }
                        )
                    }
                    '#microsoft.graph.directoryRole' {
                        #Ignore, already handeled in a different way
                    }
                    default {
                        Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Unknown member type: $($member.'@odata.type') for user $($user.Id)"
                    }
                }
            }
        }


        #Get users owned objects (do not contain devices)
        $UserOwnedSP        = [System.Collections.ArrayList]::new()
		$UserOwnedAppRegs   = [System.Collections.ArrayList]::new()
        $UserOwnedGroups  	= [System.Collections.ArrayList]::new()
        if ($UserOwnedObjectsRaw.ContainsKey($item.Id)) {
            foreach ($OwnedObject in $UserOwnedObjectsRaw[$item.Id]) {
                switch ($OwnedObject.'@odata.type') {
        
                    '#microsoft.graph.servicePrincipal' {
                        [void]$UserOwnedSP.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }
        
                    '#microsoft.graph.application' {
                        [void]$UserOwnedAppRegs.Add(
                            [PSCustomObject]@{
                                Id = $OwnedObject.Id
                            }
                        )
                    }
        
                    '#microsoft.graph.group' {
                        [void]$UserOwnedGroups.Add(
                            [PSCustomObject]@{
                                Id             = $OwnedObject.Id
                                AssignmentType = 'Active'
                            }
                        )
                    }
        
                    default {
                        Write-LogVerbose -CallerPSCmdlet $PSCmdlet -Message "Unknown owned object type: $($OwnedObject.'@odata.type') for user $($user.Id)"
                    }
                }
            }
        }

        #Get users owned devices
        $DeviceOwner = [System.Collections.ArrayList]::new()
        if ($DeviceOwnerRaw.ContainsKey($item.Id)) {
            foreach ($Device in $DeviceOwnerRaw[$item.Id]) {
                [void]$DeviceOwner.Add(
                    [PSCustomObject]@{
                        displayName = $Device.displayName
                        operatingSystem     = $Device.operatingSystem
                        approximateLastSignInDateTime = $Device.approximateLastSignInDateTime
                        accountEnabled = $Device.accountEnabled
                    }
                )
            }
        } 

        #Get users registered devices
        $DeviceRegistered = [System.Collections.ArrayList]::new()
        if ($DeviceRegisteredRaw.ContainsKey($item.Id)) {
            foreach ($Device in $DeviceRegisteredRaw[$item.Id]) {
                [void]$DeviceRegistered.Add(
                    [PSCustomObject]@{
                        displayName = $Device.displayName
                        operatingSystem     = $Device.operatingSystem
                        approximateLastSignInDateTime = $Device.approximateLastSignInDateTime
                        accountEnabled = $Device.accountEnabled
                    }
                )
            }
        } 

        if ($TenantPimForGroupsAssignments) {
            if ($UserGroupMapping.ContainsKey($item.Id)) {
                # Filter to retrieve only groupId values where accessId is "member"
                $memberGroups = $UserGroupMapping[$item.Id] | Where-Object { $_.accessId -eq "member" } | Select-Object @{Name="id"; Expression={$_.groupId}},@{Label='AssignmentType'; Expression={'Eligible'}}
                $ownerGroups = $UserGroupMapping[$item.Id] | Where-Object { $_.accessId -eq "owner" } | Select-Object @{Name="id"; Expression={$_.groupId}},@{Label='AssignmentType'; Expression={'Eligible'}}
                # Ensure $memberGroups contains values before merging
                if ($memberGroups -and @($memberGroups).Count -gt 0) {
                    # Rebuild $UserMemberGroups as an array of objects with the new IDs
                    $UserMemberGroups = $UserMemberGroups + $memberGroups
                }

                # Ensure $ownerGroups contains values before merging
                if ($ownerGroups -and @($ownerGroups).Count -gt 0) {
                    # Rebuild $UserOwnedGroups as an array of objects with the new IDs
                    $UserOwnedGroups = $UserOwnedGroups + $ownerGroups

                }
            }
        }

        #Get details for each SP
        $SPOwnerDetails = foreach ($object in $UserOwnedSP) {
            $MatchingEnterpriseApp = $EnterpriseApps[$($Object.id)]

            if ($MatchingEnterpriseApp.Foreign) {
                $AppLock = "Unknown (Foreign App)"
            } else {
                $MatchingAppReg = $AppRegistrations.Values | Where-Object { $_.AppId -eq $MatchingEnterpriseApp.AppId }
                $AppLock = $MatchingAppReg.AppLock
            }

            if (@($MatchingEnterpriseApp).count -ge 1) {
                [PSCustomObject]@{ 
                    Id = $MatchingEnterpriseApp.Id
                    DisplayName = $MatchingEnterpriseApp.DisplayName
                    AppLock = $AppLock
                    GroupMembership = $MatchingEnterpriseApp.GrpMem
                    GroupOwnership = $MatchingEnterpriseApp.GrpOwn
                    AppOwnership = $MatchingEnterpriseApp.AppOwn
                    EntraRoles = $MatchingEnterpriseApp.EntraRoles
                    AzureRoles = $MatchingEnterpriseApp.AzureRoles
                    ApiDangerous = $MatchingEnterpriseApp.ApiDangerous
                    ApiHigh = $MatchingEnterpriseApp.ApiHigh
                    ApiMedium = $MatchingEnterpriseApp.ApiMedium
                    ApiLow = $MatchingEnterpriseApp.ApiLow
                    ApiMisc = $MatchingEnterpriseApp.ApiMisc
                    Warnings = $MatchingEnterpriseApp.Warnings
                    Impact = $MatchingEnterpriseApp.Impact
                }
            }
        }

        #Get details for each AppRegistration
        $AppRegOwnerDetails = foreach ($object in $UserOwnedAppRegs) {
            $MatchingAppReg = $AppRegistrations[$($Object.id)]
            if (@($MatchingAppReg).count -ge 1) {
                [PSCustomObject]@{ 
                    Id = $MatchingAppReg.Id
                    DisplayName = $MatchingAppReg.DisplayName
                    SignInAudience = $MatchingAppReg.SignInAudience
                    AppRoles = $MatchingAppReg.AppRoles
                    Impact = $MatchingAppReg.Impact
                }
            }
        }

        #Get details for each Group
        $GroupOwnerDetails = foreach ($object in $UserOwnedGroups) {
            $MatchingGroup = $AllGroupsDetails[$($Object.id)]
            if (@($MatchingGroup).count -ge 1) {
                [PSCustomObject]@{ 
                    Id = $MatchingGroup.Id
                    DisplayName = $MatchingGroup.DisplayName
                    Type = $MatchingGroup.Type
                    Public = $MatchingGroup.Visibility
                    RoleAssignable = $MatchingGroup.RoleAssignable
                    OnPrem = $MatchingGroup.OnPrem
                    Dynamic = $MatchingGroup.Dynamic
                    EntraRoles = $MatchingGroup.EntraRoles
                    CAPs = $MatchingGroup.CAPs
                    AzureRoles = $MatchingGroup.AzureRoles
                    AppRoles = $MatchingGroup.AppRoles
                    Users = $MatchingGroup.Users
                    Impact = $MatchingGroup.Impact
                    ImpactOrg = $MatchingGroup.ImpactOrg
                    AssignmentType = $object.AssignmentType
                }
            }
        }

        #Sort by impact
        $GroupOwnerDetails = $GroupOwnerDetails | Sort-Object -Property Impact -Descending

        #Get details for each Group
        $GroupMemberDetails = foreach ($object in $UserMemberGroups) {
            $MatchingGroup = $AllGroupsDetails[$($Object.id)]
            if (@($MatchingGroup).count -ge 1) {
                [PSCustomObject]@{ 
                    Id = $MatchingGroup.Id
                    DisplayName = $MatchingGroup.DisplayName
                    Type = $MatchingGroup.Type
                    Public = $MatchingGroup.Visibility
                    RoleAssignable = $MatchingGroup.RoleAssignable
                    OnPrem = $MatchingGroup.OnPrem
                    Dynamic = $MatchingGroup.Dynamic
                    EntraRoles = $MatchingGroup.EntraRoles
                    CAPs = $MatchingGroup.CAPs
                    AzureRoles = $MatchingGroup.AzureRoles
                    AppRoles = $MatchingGroup.AppRoles
                    Users = $MatchingGroup.Users
                    Impact = $MatchingGroup.Impact
                    ImpactOrg = $MatchingGroup.ImpactOrg
                    AssignmentType = $object.AssignmentType
                    Warnings = $MatchingGroup.Warnings
                }
            }
        } 
        #Sort by impact
        $GroupMemberDetails = $GroupMemberDetails | Sort-Object -Property Impact -Descending


        $UserDirectAppRoles = $GLOBALUserAppRoles[$item.Id]
        if ($null -eq $UserDirectAppRoles) {
            $UserDirectAppRolesCount = 0
        } else { 
            $UserDirectAppRolesCount = @($UserDirectAppRoles).Count 
        }


        # For all users check if there are Azure IAM assignments
        if ($GLOBALAzurePsChecks) {
            #Use function to get the Azure Roles for each object
            $AzureRoleDetails = Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $item.Id
            # Update the Roles property only if there are matching roles
            if ($null -eq $AzureRoleDetails) {$AzureRoleCount = 0} else { $AzureRoleCount = @($AzureRoleDetails).Count }
        } else {
            $AzureRoleCount = "?"
        }

        #Check if the user is MFA-capable
        $IsMfaCapable = $UserAuthMethodsTable[$item.Id]

        #Default value if not checked
        if ($null -eq $IsMfaCapable) {
            $IsMfaCapable = "?"
        }

    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################   

        #Increase the risk score if user is not MFA capable and is not the sync account
        if ($IsMfaCapable -ne "?" -and $IsMfaCapable -ne $true -and $item.DisplayName -ne "On-Premises Directory Synchronization Service Account" ) {
            $Likelihood += $UserLikelihood["NoMFA"]
        }
        
        #Process owned SP
        if ($SPOwnerDetails) {
            #Add the impact score of the owned SP
            $AddImpact = 0
            $SpCount = 0
            $SpCountAppLock = 0
            $SpCountAppLockUnknown = 0
            $SpCountAppLockNo = 0
            foreach ($object in $SPOwnerDetails) {
                $SpCount ++
                if ($object.AppLock -eq $false) {
                    #takeover impact from SP
                    $AddImpact += $object.Impact
                    $SpCountAppLock ++
                } elseif ($object.AppLock -eq $true) {
                    $SpCountAppLockNo ++
                    #Otherwise, add SP impact or a base value (the lower one)
                    if ($object.Impact -le $UserImpact["SpOwnAppLock"]) {
                        $AddImpact += $object.Impact
                    } else {
                        $AddImpact += $UserImpact["SpOwnAppLock"]
                    }
                } else {
                    $SpCountAppLockUnknown ++
                    #takeover impact from SP
                    $AddImpact += $object.Impact
                }
            }
            $Warnings += "User is owner of $SpCount SP (AppLock:$SpCountAppLock/$SpCount, Unknown:$SpCountAppLockUnknown)"
            $Impact += $AddImpact
        }

        #Process owned AppRegistrations
        if ($AppRegOwnerDetails) {
            $AppRegCount = 0
            $AddImpact = 0
            foreach ($object in $AppRegOwnerDetails) {
                $AppRegCount++
                #Apply impact score from App Registration
                $AddImpact += $object.Impact
            }
            $Impact += $AddImpact
            $Warnings += "User is owner of $AppRegCount App Registrations"
        }


        #Process owned groups
        if ($GroupOwnerDetails) {
            $GroupCount = 0
            $AddImpact = 0
            $EntraRolesCount = 0
            $CAPs = 0
            $AzureRolesCount = 0
            $AppRolesCount = 0
            $Message = ""
            $MessageParts = @()

            foreach ($object in $GroupOwnerDetails) {
                $GroupCount++

                #Take over Impact from Group
                $AddImpact += $object.Impact
                $EntraRolesCount += $object.EntraRoles
                #Only process Caps if user has permission to them
                if ($GLOBALPermissionForCaps) {
                    $CAPs += $object.CAPs
                }
                if ($object.AzureRoles -is [int]) {$AzureRolesCount += $object.AzureRoles} else {$AzureRolesCount += 0}

                $AppRolesCount += $object.AppRoles
            }
            $Impact += $AddImpact

            #If any user is owner of a role assignable group the likelihood score has to be lowered
            if ($GroupOwnerDetails.RoleAssignable -contains $true) {
                $protected = $true
            }

            if (($EntraRolesCount + $CAPs + $AzureRolesCount + $AppRolesCount) -ge 1) {
                if ($EntraRolesCount -ge 1) {
                    $MessageParts += "EntraRoles:$EntraRolesCount"
                }
                if ($AzureRolesCount -ge 1) {
                    $MessageParts += "AzureRoles:$AzureRolesCount"
                }
                if ($AppRolesCount -ge 1) {
                    $MessageParts += "AppRoles:$AppRolesCount"
                }
                if ($CAPs -ge 1) {
                    $MessageParts += "CAPs:$CAPs"
                }
                $Message = $MessageParts -join ' / '
                $Warnings += "Owns privileged group ($Message)"
            }
            $EntraRolesTroughGroupOwnership = $EntraRolesCount
            $AzureRolesTroughGroupOwnership = $AzureRolesCount
        }

        #Process member groups
        if ($GroupMemberDetails) {
            $GroupCount = 0
            $AddImpact = 0
            $EntraRolesCount = 0
            $ObjectsWithCaps = 0
            $AzureRolesCount = 0
            $AppRolesCount = 0
            $Message = ""
            $MessageParts = @()

            foreach ($object in $GroupMemberDetails) {
                $GroupCount++

                #Take over Impact from Group
                $AddImpact += $object.Impact
                $EntraRolesCount += $object.EntraRoles

                #Only process Caps if user had permission to enumerate them
                if ($GLOBALPermissionForCaps -and $object.CAPs -ge 1) {
                    $ObjectsWithCaps++
                }
                
                if ($object.AzureRoles -is [int]) {$AzureRolesCount += $object.AzureRoles} else {$AzureRolesCount += 0}
                $AppRolesCount += $object.AppRoles
            }

            #Removing the impact of CAPs if the user just is a member of a group in a CAP. Must match the value from the group script $GroupImpactScore
            $AddImpact -= ($ObjectsWithCaps * 50)

            $Impact += $AddImpact

            #If any user is member of a role assignable group the likelihood score has to be lowered
            if ($GroupMemberDetails.RoleAssignable -contains $true) {
                $protected = $true
            }

            if (($EntraRolesCount + $AzureRolesCount) -ge 1) {
                if ($EntraRolesCount -ge 1) {
                    $MessageParts += "EntraRoles:$EntraRolesCount"
                }
                if ($AzureRolesCount -ge 1) {
                    $MessageParts += "AzureRoles:$AzureRolesCount"
                }
                $Message = $MessageParts -join ' / '
                $Warnings += "Member of privileged group ($Message)"
            }
            $EntraRolesTroughGroupMembership = $EntraRolesCount
            $AzureRolesTroughGroupMembership = $AzureRolesCount
        }

        #If any user is member of a AU which is management restricted the likelihood score has to be lowered
        if ($AUMember.isMemberManagementRestricted -contains $true) {
            $protected = $true
        }

        if ($item.DisplayName -eq "On-Premises Directory Synchronization Service Account") {
            $SyncAcc = $true

            if ($item.UserPrincipalName.StartsWith("Sync_")){
                $SyncAccType = "Connect Sync"
            } elseif ($item.UserPrincipalName.StartsWith("ADToAADSyncServiceAccount@")) {
                $SyncAccType = "Cloud Sync"
                #Mark cloud sync account to skip inactivity check
                $CloudSyncAccount = $true
            }
            $Warnings += "Entra $SyncAccType account"
        } else {
            $SyncAcc = $false
            $CloudSyncAccount = $false
        }
        
        $OnPremExtensions = $item.OnPremisesExtensionAttributes.PSObject.Properties | Where-Object {$null -ne $_.Value -and $_.Name -ne "AdditionalProperties"} | select-object Name,Value

        # Find matching roles in Entra role assignments where the PrincipalId matches the user's Id
        $MatchingEntraRoles = $TenantRoleAssignments[$item.Id]
        foreach ($Role in $MatchingEntraRoles) { 

            $Roleinfo = [PSCustomObject]@{
                DisplayName       = $role.DisplayName
                AssignmentType    = $role.AssignmentType
                IsPrivileged      = $role.IsPrivileged
                IsEnabled         = $role.IsEnabled
                IsBuiltIn         = $role.IsBuiltIn
                RoleTier          = $role.RoleTier
                DirectoryScopeId  = $role.DirectoryScopeId
                ScopeResolved     = $role.ScopeResolved
            }
            $UserEntraRoles += $Roleinfo

            #Set user to protected if not marked as protected already and if is not and unprotected role
            if (-not $protected -and ($UnprotectedRoles -notcontains $role.DisplayName)) {
                $Protected = $true
            }
        }

        #Process Entra Role assignments
        #Use function to get the impact score and warning message for assigned Entra roles
        if (($UserEntraRoles | Measure-Object).count -ge 1) {
            $EntraRolesProcessedDetails = Invoke-EntraRoleProcessing -RoleDetails $UserEntraRoles
            $Warnings += $EntraRolesProcessedDetails.Warning
            $Impact += $EntraRolesProcessedDetails.ImpactScore

            #Check if the sync account has more than one role or an unexpected role
            if ($SyncAcc -and (@($UserEntraRoles).count -gt 1 -or $UserEntraRoles.DisplayName -notcontains "Directory Synchronization Accounts")) {
                $Warnings += "Sync account with extensive privileges"
            }
            #Check if another user has the Directory Sync role
            if (!$SyncAcc -and $UserEntraRoles.DisplayName -contains "Directory Synchronization Accounts") {
                $Warnings += "Directory Synchronization Role on non-sync user!"
            }
        }
       
        #Check app roles for sensitive keywords
        if ($UserDirectAppRolesCount -ge 1){
            $keywords = @("admin", "critical")
            $SensitiveCounter = 0

            $UserDirectAppRoles | ForEach-Object {
                $matchFound = $false
                if ($_.AppRoleEnabled -eq $true) {
                    foreach ($keyword in $keywords) {
                        if ($_.AppRoleDisplayName -like "*$keyword*" -or $_.AppRoleDescription -like "*$keyword*") {
                            $matchFound = $true
                            break
                        }
                    }
                    if ($matchFound) {
                        $Impact += $UserImpact["DirectAppRoleSensitive"]
                        $SensitiveCounter++
                    } else {
                        $Impact += $UserImpact["DirectAppRoleNormal"]
                    }
                }
            }
            if ($SensitiveCounter -ge 1) {
                $Warnings += "Potentially sensitive AppRole directly assigned"
            }
        }


        #Check last sign-in dates
        if ($PermissionUserSignInActivity) {
            #Calculate number of inactive days
            if($null -eq $LastInteractiveSignIn) {
                $LastInteractiveSignIn = "Never logged in"
                $InactiveDays_InteractiveSignIn = "-"
            }
            else {
                $InactiveDays_InteractiveSignIn = (New-TimeSpan -Start $LastInteractiveSignIn).Days
            }
            if($null -eq $LastNonInteractiveSignIn) {
                $LastNonInteractiveSignIn = "Never Logged In"
                $InactiveDays_NonInteractiveSignIn = "-"
            }
            else {
                $InactiveDays_NonInteractiveSignIn = (New-TimeSpan -Start $LastNonInteractiveSignIn).Days
            }
            if($null -eq $LastSuccessfulSignInTime) {
                #Property exist since 12.2023
                $LastSuccessfulSignInTime = "Never or before 2024"
                $InactiveDays_lastsuccessfulSignin = "-"
            }
            else {
                $InactiveDays_lastsuccessfulSignin = (New-TimeSpan -Start $LastSuccessfulSignInTime).Days
            }


            if ($InactiveDays_lastsuccessfulSignin -ge 180 -or ($InactiveDays_lastsuccessfulSignin -eq "-" -and $CreatedDays -gt 180 -and -not $CloudSyncAccount)) {
                $Inactive = $true
            }
        } else {
            $InactiveDays_lastsuccessfulSignin = "?"
            $Inactive = "?"
        }


        if ($Protected) {
            $Likelihood += $UserLikelihood["Protected"]
        }

        if ($AzureRoleCount -ge 1) {
            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            $Warnings += $AzureRolesProcessedDetails.Warning
            $Impact += $AzureRolesProcessedDetails.ImpactScore
        }

    #Format warning messages
    $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }
        
        #Combine Direct assigned Entra roles + roles trough group
        $TotalEntraRoles = $EntraRolesTroughGroupOwnership + $EntraRolesTroughGroupMembership + @($UserEntraRoles).count

        if ($GLOBALAzurePsChecks) {
            $TotalAzureRoles = $AzureRolesTroughGroupOwnership + $AzureRolesTroughGroupMembership + $AzureRoleCount
        } else {
            $TotalAzureRoles = $AzureRoleCount
        }
        
        
        #Calc risk
        $Risk = [math]::Round(($Impact * $Likelihood))

        #Create custom object
        $UserDetails = [PSCustomObject]@{ 
            Id = $item.Id 
            DisplayName = $item.DisplayName
            UPNlink = "<a href=#$($item.id)>$($item.UserPrincipalName)</a>"
            UPN = $item.UserPrincipalName
            Enabled = $item.AccountEnabled
            UserType = $item.UserType
            Licenses = $($item.AssignedLicenses).count
            LicenseStatus = $LicenseStatus
            OnPrem = $OnPrem
            BusinessPhones = $item.BusinessPhones
            Department = $item.Department
            JobTitle = $item.JobTitle
            OtherMails = $item.OtherMails
            CreatedDateTime = $item.CreatedDateTime
            CreatedDays = $CreatedDays
            LastInteractiveSignInDateTime = $LastInteractiveSignIn
            InactiveDays_InteractiveSignIn = $InactiveDays_InteractiveSignIn
            LastNonInteractiveSignInDateTime = $LastNonInteractiveSignIn
            InactiveDays_NonInteractiveSignIn = $InactiveDays_NonInteractiveSignIn
            lastSuccessfulSignInDateTime = $LastSuccessfulSignInTime
            LastSignInDays = $InactiveDays_lastsuccessfulSignin
            Inactive = $Inactive
            AzureRoles = $TotalAzureRoles
            AzureRoleDetails = $AzureRoleDetails
            OnPremExtensionsDetails = $OnPremExtensions
            GrpMem = @($GroupMemberDetails).count
            GrpOwn = @($GroupOwnerDetails).count
            AuUnits = @($AUMember).count
            EntraRoles = $TotalEntraRoles
            AppRegOwn = @($AppRegOwnerDetails).count
            SPOwn = @($SPOwnerDetails).count
            DeviceOwn = @($DeviceOwner).count
            UserMemberGroups = $GroupMemberDetails
            AUMemberDetails = $AUMember
            Protected = $protected
            AppRoles = $UserDirectAppRolesCount
            AppRolesDetails = $UserDirectAppRoles
            GroupOwnerDetails = $GroupOwnerDetails
            AppRegOwnerDetails = $AppRegOwnerDetails
            SPOwnerDetails = $SPOwnerDetails
            DeviceOwnerDetails = $DeviceOwner
            DeviceRegisteredDetails = $DeviceRegistered
            MfaCap = $IsMfaCapable
            DeviceReg = @($DeviceRegistered).count
            RolesDetails = $UserEntraRoles
            Impact = [math]::Round($Impact)
            Likelihood = [math]::Round($Likelihood,1)
            Risk = $Risk
            Warnings = $Warnings
        } 

        
        [void]$AllUsersDetails.Add($UserDetails)


    }
    write-host "[*] Processing results"

    #Define output of the main table
    $tableOutput = $AllUsersDetails | Sort-Object Risk -Descending | select-object UPN,UPNlink,Enabled,UserType,OnPrem,Licenses,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,AzureRoles,AppRoles,AppRegOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,Impact,Likelihood,Risk,Warnings
    $AppendixInactive = $AllUsersDetails | Where-Object {$_.Inactive -eq $true -and $_.Enabled -eq $true}
    $InactiveUsersCount = @($AppendixInactive).count


    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllUsersDetails | Sort-Object Risk -Descending

    # Get the total count of group memberships. If this is to high the amount groups in the HTML report will be limited
    $TotalMemberGroups = @($AllUsersDetails.UserMemberGroups).count
    if ($TotalMemberGroups -ge 20000) {
        $LimitGroupMembers = $true
        $WarningReport += "GroupMembership: Only 10 groups are displayed to ensure HTML performance."
    } else {
        $LimitGroupMembers = $false
    }

    # Initialize StringBuilders
    $DetailTxtBuilder  = [System.Text.StringBuilder]::new()

    #Enum the details
    foreach ($item in $details) {

        $ReportingUserInfo = @()
        $ReportingLoginDetails = @()
        $ReportingRoles = @()
        $ReportingGroupOwner = @()
        $ReportingOwnerAppRegistration = @()
        $ReportingOwnerSP = @()
        $ReportingOwnerDevice = @()
        $ReportingOnPremExtensionsDetails = @()
        $ReportingRegisteredDevice = @()
        $ReportingAdminUnits = @()
        $ReportingAppRoles = @()
        $ReportingMemberGroup = @()
        $ReportingAzureRoles = @()
        $ReportingLicenses = @()

        $UserCounter ++
        [void]$DetailTxtBuilder.AppendLine("##############################################################################################################################################################################################################")

        $ReportingUserInfo = [pscustomobject]@{
            "Display Name" = $($item.DisplayName)
            "User UPN" = $($item.Upn)
            "User ObjectID" = $($item.Id)
            "Protected" = $($item.Protected)
            "RiskScore" = $($item.Risk)
            "UserType" = $($item.UserType)
            "Created" = "$($item.CreatedDateTime) ($($item.CreatedDays) days ago)"
        }
        #Add sign-in info to the list if it's not shown in a dedicated table
        if ($null -ne $item.Department) {
            $ReportingUserInfo | Add-Member -NotePropertyName Department -NotePropertyValue $item.Department
        }
        if ($null -ne $item.JobTitle) {
            $ReportingUserInfo | Add-Member -NotePropertyName JobTitle -NotePropertyValue $item.JobTitle
        }
        if ($item.OtherMails -ne '') {
            $ReportingUserInfo | Add-Member -NotePropertyName OtherMails -NotePropertyValue ($item.OtherMails | Out-String)
        }

        if ($item.Warnings -ne '') {
            $ReportingUserInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingUserInfo | Out-String))

        #Hide Login details section if user had not enough permissions to read the attributes
        if ($PermissionUserSignInActivity) {
            $ReportingLoginDetails = [pscustomobject]@{
                "Last successful log-in" = "$($item.lastSuccessfulSignInDateTime) ($($item.LastSignInDays) days ago)"
                "Last interactive log-in attempt" = "$($item.LastInteractiveSignInDateTime) ($($item.InactiveDays_InteractiveSignIn) days ago)"
                "Last non-interactive log-in" = "$($item.LastNonInteractiveSignInDateTime) ($($item.InactiveDays_NonInteractiveSignIn) days ago)"
            }           
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Login Details")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Last successful log-in: $($item.lastSuccessfulSignInDateTime) ($($item.LastSignInDays) days ago)")
            [void]$DetailTxtBuilder.AppendLine("Last interactive log-in attempt: $($item.LastInteractiveSignInDateTime) ($($item.InactiveDays_InteractiveSignIn) days ago)")
            [void]$DetailTxtBuilder.AppendLine("Last non-interactive log-in: $($item.LastNonInteractiveSignInDateTime) ($($item.InactiveDays_NonInteractiveSignIn) days ago)")
            [void]$DetailTxtBuilder.AppendLine()
        }

        
        if (@($item.RolesDetails).count -ge 1) {
            $ReportingRoles = foreach ($role in $($item.RolesDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $($role.DisplayName)
                    "AssignmentType" = $($role.AssignmentType)
                    "Tier Level" = $($role.RoleTier)
                    "Privileged" = $($role.isPrivileged)
                    "Builtin" = $($role.IsBuiltin)
                    "Scoped to" = "$($role.ScopeResolved.DisplayName) ($($role.ScopeResolved.Type))"
                }
            }

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Entra Role Assignments")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles| format-table | Out-String))
        }

        if (@($item.GroupOwnerDetails).count -ge 1) {
            $ReportingGroupOwner = foreach ($object in $($item.GroupOwnerDetails)) {
                [pscustomobject]@{ 
                    "AssignmentType" = $($object.AssignmentType)
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                    "Type" = $($object.Type)
                    "OnPrem" = $($object.OnPrem)
                    "EntraRoles" = $($object.EntraRoles)
                    "AzureRoles" = $($object.AzureRoles)
                    "AppRoles" = $($object.AppRoles)
                    "CAPs" = $($object.CAPs)
                    "Users" = $($object.Users)
                    "Impact" = $($object.Impact)
                    "Warnings" = $($object.Warnings)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of Groups")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingGroupOwner | format-table -Property AssignmentType,DisplayName,Type,OnPrem,EntraRoles,AzureRoles,AppRoles,CAPs,Users,Impact,Warnings | Out-String))
            $ReportingGroupOwner  = foreach ($obj in $ReportingGroupOwner) {
                [pscustomobject]@{
                    AssignmentType          = $obj.AssignmentType
                    DisplayName             = $obj.DisplayNameLink
                    Type                    = $obj.Type
                    OnPrem                  = $obj.OnPrem
                    EntraRoles              = $obj.EntraRoles
                    AzureRoles              = $obj.AzureRoles
                    AppRoles                = $obj.AppRoles
                    CAPs                    = $obj.CAPs
                    Users                   = $obj.Users
                    Impact                  = $obj.Impact
                    Warnings                = $obj.Warnings
                }
            }
        }

        if (@($item.AppRegOwnerDetails).count -ge 1) {
            $ReportingOwnerAppRegistration = foreach ($app in $($item.AppRegOwnerDetails)) {
                [pscustomobject]@{ 
                    "DisplayName" = $($app.DisplayName)
                    "DisplayNameLink" = "<a href=AppRegistration_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($app.Id)>$($app.DisplayName)</a>"
                    "SignInAudience" = $($app.SignInAudience)
                    "AppRoles" = $($app.AppRoles)
                    "Impact" = $($app.Impact)
                }            
            }
            #Sort based on the impact
            $ReportingOwnerAppRegistration = $ReportingOwnerAppRegistration | Sort-Object -Property Impact -Descending

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of App Registration")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerAppRegistration | format-table -Property DisplayName,SignInAudience,AppRoles,Impact | Out-String))
            $ReportingOwnerAppRegistration = foreach ($obj in $ReportingOwnerAppRegistration) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    SignInAudience          = $obj.SignInAudience
                    AppRoles                = $obj.AppRoles
                    Impact                  = $obj.Impact
                }
            }
        }


        if (@($item.SPOwnerDetails).count -ge 1) {
            $ReportingOwnerSP  = foreach ($app in $($item.SPOwnerDetails)) {
                [pscustomobject]@{ 
                    "DisplayName" = $($app.DisplayName)
                    "DisplayNameLink" = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($app.Id)>$($app.DisplayName)</a>"
                    "AppLock" = $($app.AppLock)
                    "GroupMembership" = $($app.GroupMembership)
                    "GroupOwnership" = $($app.GroupOwnership)
                    "AppOwnership" = $($app.AppOwnership)
                    "EntraRoles" = $($app.EntraRoles)
                    "AzureRoles" = $($app.GroupOwnership)
                    "APIPermission" = "D:$($app.ApiDangerous) / H:$($app.ApiHigh) / M:$($app.ApiMedium) / L:$($app.ApiLow) / U:$($app.ApiMisc)"
                    "Warnings" = $($app.Warnings)
                }
            }
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of Service Principal")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerSP | format-table -Property DisplayName,AppLock,GroupMembership,GroupOwnership,AppOwnership,EntraRoles,AzureRoles,APIPermission,Warnings | Out-String))
            $ReportingOwnerSP  = foreach ($obj in $ReportingOwnerSP) {
                [pscustomobject]@{
                    DisplayName             = $obj.DisplayNameLink
                    AppLock             = $obj.AppLock
                    GroupMembership         = $obj.GroupMembership
                    AppOwnership            = $obj.AppOwnership
                    EntraRoles              = $obj.EntraRoles
                    AzureRoles              = $obj.AzureRoles
                    APIPermission           = $obj.APIPermission
                    Warnings                = $obj.Warnings
                }
            }
        }


        if (@($item.DeviceOwnerDetails).count -ge 1) {
            $ReportingOwnerDevice = foreach ($device in $($item.DeviceOwnerDetails)) {
                [pscustomobject]@{ 
                    "Device name" = $($device.displayName)
                    "Enabled" = $($device.accountEnabled)
                    "OS" = $($device.operatingSystem)
                    "Last sign-in" = $($device.approximateLastSignInDateTime)
                }
            }
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Owner of Devices")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOwnerDevice | Out-String))
        }

        #On-prem attributes
        if (@($item.OnPremExtensionsDetails).count -ge 1) {
            $ReportingOnPremExtensionsDetails = $item.OnPremExtensionsDetails
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("On-Prem Extension Attributes")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingOnPremExtensionsDetails | format-table | Out-String))
            
        }

        #Registered devices
        if (@($item.DeviceRegisteredDetails).count -ge 1) {
            $ReportingRegisteredDevice = foreach ($device in $($item.DeviceRegisteredDetails)) {
                [pscustomobject]@{ 
                    "Device name" = $($device.displayName)
                    "Enabled" = $($device.accountEnabled)
                    "OS" = $($device.operatingSystem)
                    "Last sign-in" = $($device.approximateLastSignInDateTime)
                }
            }
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Registered Devices")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRegisteredDevice | Out-String))
        }   

        #AU Devices
        if (@($item.AUMemberDetails).count -ge 1) {       
            $ReportingAdminUnits = foreach ($Au in $($item.AUMemberDetails)) {
                [pscustomobject]@{ 
                    "AU Name" = $($Au.DisplayName)
                    "isMemberManagementRestricted" = $($Au.isMemberManagementRestricted)
                    
                }
            }

            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Administrative Units")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAdminUnits | format-table))
        }

        #Directly assigned AppRoles
        if ($item.AppRoles -ge 1) {
           
            $ReportingAppRoles = foreach ($object in $($item.AppRolesDetails)) {
                [pscustomobject]@{ 
                    "AppRoleName" = $($object.AppRoleDisplayName)
                    "Enabled" = $($object.AppRoleEnabled)
                    "Description" = $($object.AppRoleDescription)
                    "AssignedtoApp" = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.AppID)>$($object.AppName)</a>"
                    "App" = "$($object.AppName)"
                }
            }
            
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Directly Assigned AppRoles")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAppRoles | format-table -Property AppRoleName,Enabled,Description,App | Out-String))
            $ReportingAppRoles  = foreach ($obj in $ReportingAppRoles) {
                [pscustomobject]@{
                    AppRoleName     = $obj.AppRoleName
                    Enabled         = $obj.Enabled
                    Description     = $obj.Description
                    AssignedtoApp   = $obj.AssignedtoApp
                }
            }
        }

        #Group Memberships
        if (@($item.UserMemberGroups).count -ge 1) {

            #Limit the number of groups if needed
            if ($LimitGroupMembers) {
                $item.UserMemberGroups = $item.UserMemberGroups | select-object -First 10
            }
            
            $ReportingMemberGroup = foreach ($object in $($item.UserMemberGroups)) {
                [pscustomobject]@{
                    "AssignmentType" = $($object.AssignmentType)
                    "DisplayName" = $($object.DisplayName)
                    "DisplayNameLink" = "<a href=Groups_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.DisplayName)</a>"
                    "Type" = $($object.Type)
                    "OnPrem" = $($object.OnPrem)
                    "EntraRoles" = $($object.EntraRoles)
                    "AzureRoles" = $($object.AzureRoles)
                    "AppRoles" = $($object.AppRoles)
                    "CAPs" = $($object.CAPs)
                    "Users" = $($object.Users)
                    "Impact" = $($object.Impact)
                    "Warnings" = $($object.Warnings)
                }
            }

            $ReportingMemberGroup = $ReportingMemberGroup | sort-object Impact -Descending
            
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine("Member of Groups")
            [void]$DetailTxtBuilder.AppendLine("-----------------------------------------------------------------")
            [void]$DetailTxtBuilder.AppendLine(($ReportingMemberGroup | format-table -Property AssignmentType,DisplayName,Type,OnPrem,EntraRoles,AzureRoles,AppRoles,CAPs,Users,Impact,Warnings | Out-String))
            $ReportingMemberGroup  = foreach ($obj in $ReportingMemberGroup) {
                [pscustomobject]@{
                    AssignmentType          = $obj.AssignmentType
                    DisplayName             = $obj.DisplayNameLink
                    Type                    = $obj.Type
                    OnPrem                  = $obj.OnPrem
                    EntraRoles              = $obj.EntraRoles
                    AzureRoles              = $obj.AzureRoles
                    AppRoles                = $obj.AppRoles
                    CAPs                    = $obj.CAPs
                    Users                   = $obj.Users
                    Impact                  = $obj.Impact
                    Warnings                = $obj.Warnings
                }
            }
        }

        ############### Azure Roles
        if ($item.AzureRoles -ge 1 ) {
            $ReportingAzureRoles = foreach ($object in $($item.AzureRoleDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $($object.RoleName)
                    "Assignment" = $($object.AssignmentType)
                    "RoleType" = $($object.RoleType)
                    "Tier Level" = $($object.RoleTier)
                    "Conditions" = $($object.Conditions)
                    "Scoped to" = $($object.Scope)
                }
            }
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | format-table | Out-String))
        }

        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.Upn
            "Object ID"       = $item.Id
            "General Information" = $ReportingUserInfo
            "Sign-In Details" = $ReportingLoginDetails
            "Entra Role Assignments" = $ReportingRoles
            "Owner of Groups" = $ReportingGroupOwner
            "Owner of App Registration" = $ReportingOwnerAppRegistration
            "Owner of Service Principal" = $ReportingOwnerSP
            "Owner of Devices" = $ReportingOwnerDevice
            "On-Prem Extension Attributes" = $ReportingOnPremExtensionsDetails
            "Registered Devices" = $ReportingRegisteredDevice
            "Administrative Units" = $ReportingAdminUnits
            "Directly Assigned AppRoles" = $ReportingAppRoles
            "Member of Groups (Transitive)" = $ReportingMemberGroup
            "Azure IAM assignments" = $ReportingAzureRoles
            "Assigned Licenses" = $ReportingLicenses
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)


    }

    $DetailOutputTxt  = $DetailTxtBuilder.ToString()

    write-host "[+] Writing log files"
    write-host ""

    $mainTable = $tableOutput | select-object -Property @{Name = "UPN"; Expression = { $_.UPNlink}},Enabled,UserType,OnPrem,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,AzureRoles,AppRoles,AppRegOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'



    #Define header HTML
    $headerHTML = [pscustomobject]@{ 
        "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
        "Executed at" = "$StartTimestamp "
        "Execution Warnings" = $WarningReport -join ' / '
    }

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Users Details</h2>
    <div style="margin: 10px 0;">
        <button id="toggle-expand">Expand All</button>
    </div>
    <div id="object-container"></div>
    <script id="object-data" type="application/json">
'@
$AllObjectDetailsHTML = $ObjectsDetailsHEAD + "`n" + $AllObjectDetailsHTML + "`n" + '</script>'

#Define header
$headerTXT = "************************************************************************************************************************
$Title Enumeration
Executed in Tenant: $($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)
Executed at: $StartTimestamp
Execution Warnings = $($WarningReport  -join ' / ')
************************************************************************************************************************
"

    # Build header section
    $headerHTML = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>$($Title) Enumeration</h1>" -As List -PostContent "<h2>$($Title) Overview</h2>"

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | select-object UPN,Enabled,UserType,OnPrem,Licenses,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,AzureRoles,AppRoles,AppRegOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    $tableOutput | format-table -Property UPN,Enabled,UserType,OnPrem,Licenses,LicenseStatus,Protected,GrpMem,GrpOwn,AuUnits,EntraRoles,AzureRoles,AppRoles,AppRegOwn,SPOwn,DeviceOwn,DeviceReg,Inactive,LastSignInDays,CreatedDays,MfaCap,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $DetailOutputTxt | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append

    write-host "[+] Details of $UsersTotalCount users stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)"
    

    If ($InactiveUsersCount -gt 0) {
        $AppendixInactive | select-object Upn,OnPrem,UserType,Licenses,Protected,GrpMem,GrpOwn,EntraRoles,AzureRoles,AppRoles,AppRegOwn,SPOwn,DeviceOwn,DeviceReg,LastSignInDays,lastSuccessfulSignInDateTime | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)_Inactive.csv" -NoTypeInformation
        write-host "[+] Details of $InactiveUsersCount inactive users written to output file: $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt and CSV file: $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)_Inactive.csv "
    }

    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title enumeration" -Head $GLOBALcss -PostContent $GLOBALJavaScript -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    #Add information to the enumeration summary
    $GuestCount = 0
    $InactiveCount = 0
    $EnabledCount = 0
    $MfaCapCount = 0
    $OnPremCount = 0
    $buckets = New-Object 'System.Collections.Generic.List[string]'

    foreach ($user in $AllUsersDetails) {
        if ($user.UserType -eq "Guest") {
            $GuestCount++
        }
        if ($user.Inactive) {
            $InactiveCount++
        }
        if ($user.Enabled) {
            $EnabledCount++
        }
        if ($user.MfaCap) {
            $MfaCapCount++
        }
        if ($user.OnPrem) {
            $OnPremCount++
        }

        # Group sign-in activity
        $lastSignIn = $user.LastSignInDays
        if ($lastSignIn -eq "-" -or [string]::IsNullOrWhiteSpace($lastSignIn)) {
            $buckets.Add("Never")
        } else {
            try {
                $bucket = if ($lastSignIn -le 30) { "0-1 month" }
                        elseif ($lastSignIn -le 60) { "1-2 months" }
                        elseif ($lastSignIn -le 90) { "2-3 months" }
                        elseif ($lastSignIn -le 120) { "3-4 months" }
                        elseif ($lastSignIn -le 150) { "4-5 months" }
                        elseif ($lastSignIn -le 180) { "5-6 months" }
                        else { "6+ months" }

                $buckets.Add($bucket)
            } catch {
                $buckets.Add("?")
            }
        }

    }
    # Store in global var
    $GlobalAuditSummary.Users.Count = $UsersTotalCount
    $GlobalAuditSummary.Users.Guests = $GuestCount
    $GlobalAuditSummary.Users.Inactive = $InactiveCount
    $GlobalAuditSummary.Users.Enabled = $EnabledCount
    $GlobalAuditSummary.Users.MfaCapable = $MfaCapCount
    $GlobalAuditSummary.Users.OnPrem = $OnPremCount

    # Group and summarize
    $buckets | Group-Object | ForEach-Object {
        $GlobalAuditSummary.Users.SignInActivity[$_.Name] = $_.Count
    }

    #Convert to Hashtable for faster searches
    $UsersHT = @{}
    foreach ($user in $AllUsersDetails) {
        $UsersHT[$user.Id] = $user
    }
    Return $UsersHT

}