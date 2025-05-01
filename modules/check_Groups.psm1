<#
	.SYNOPSIS
	   Enumerates groups and evaluates their configurations, ownership, roles, and risk posture.

#>

function Invoke-CheckGroups {

    ############################## Parameter section ########################
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)][string]$OutputFolder = ".",
        [Parameter(Mandatory=$false)][int]$HTMLMemberLimit = 20,
        [Parameter(Mandatory=$false)][switch]$SkipAutoRefresh = $false,
        [Parameter(Mandatory=$false)][Object[]]$AdminUnitWithMembers,
        [Parameter(Mandatory=$true)][Object[]]$CurrentTenant,
        [Parameter(Mandatory=$false)][Object[]]$ConditionalAccessPolicies,
        [Parameter(Mandatory=$false)][hashtable]$AzureIAMAssignments,
        [Parameter(Mandatory=$true)][hashtable]$TenantRoleAssignments,
        [Parameter(Mandatory=$true)][String[]]$StartTimestamp,
        [Parameter(Mandatory=$false)][Object[]]$TenantPimForGroupsAssignments
    )

    ############################## Function section ########################

    #Function to check if SP is foreign.
    function CheckSP($Object){

        #Check if the SP is a managed identity
        if ($object.servicePrincipalType -eq "ManagedIdentity") {
            $ForeignTenant = $false
            $DefaultMS = $false
        } else {
            if ($Object.AppOwnerOrganizationId -eq $($CurrentTenant).id) {
                $ForeignTenant = $false
            } else {
                $ForeignTenant = $true
            }

            #Check if SP is an MS default
            if ($GLOBALMsTenantIds -contains $Object.AppOwnerOrganizationId) {
                $DefaultMS = $true
            } else {
                $DefaultMS = $false
            }
        }

        [PSCustomObject]@{ 
            Id = $Object.id
            DisplayName = $Object.displayName
            Foreign = $ForeignTenant
            PublisherName = $Object.PublisherName
            SPType = $Object.servicePrincipalType
            DefaultMS = $DefaultMS
        }

    }

    ############################## Script section ########################

    # Check token and trigger refresh if required
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    # Define basic variables
    $Title = "Groups"
    $ProgressCounter = 0
    $TokenCheckLimit = 5000  # Define recheck limit for token lifetime. In large environments the access token might expire during the test.
    $GroupScriptWarningList = @()
    $NestedGroupsHighvalue = @()
	$AllGroupsDetails = [System.Collections.ArrayList]::new()
    $AllObjectDetailsHTML = [System.Collections.ArrayList]::new()
    $DetailOutputTxt = ""
    if (-not $GLOBALGraphExtendedChecks) {$GroupScriptWarningList += "Only active role assignments assessed!"}

    $GroupImpactScore = @{
        "M365Group"                 = 1
        "HiddenGAL"                 = 1 
        "Distribution"              = 0.5
        "SecurityEnabled"           = 2
        "AzureRole"                 = 100
        "AppRole"                   = 10
        "CAP"                       = 50
    }
    $GroupLikelihoodScore = @{
        "PublicM365Group"           = 100
        "Member"                    = 0.1
        "MemberOnPrem"              = 2
        "DirectOwnerCloud"          = 1
        "DirectOwnerOnprem"         = 2
        "NestedOwnerCloud"          = 2
        "NestedOwnerOnprem"         = 3
        "PIMforGroupsOwnersGroup"   = 3
        "NestedGroup"               = 2
        "DynamicGroup"              = 5
        "DynamicGroupDangerous"     = 20
        "ExternalSPMemberOwner"     = 50
        "InternalSPMemberOwner"     = 5
        "BaseNotProtected"          = 5
        "GuestMemberOwner"          = 5
    }

    
    if ($TenantPimForGroupsAssignments) {

        # Hashtable for all owners for faster lookup in each group
        $PimForGroupsEligibleOwnersHT = @{}
        $PimForGroupsEligibleOwnerParentGroupHT = @{}
        foreach ($assignment in $TenantPimForGroupsAssignments) {
            if ($assignment.accessId -eq "owner") {
                # Check if groupId already exists in the hashtable
                if (-not $PimForGroupsEligibleOwnersHT.ContainsKey($assignment.groupId)) {
                    $PimForGroupsEligibleOwnersHT[$assignment.groupId] = @()  # Initialize as an empty array
                }
        
                #Add Properties depending on the object type
                if ($assignment.Type -eq "User") {
                    $OwnerInfo = [PSCustomObject]@{
                        Id  =                   $assignment.principalId
                        DisplayName  =          $assignment.DisplayName
                        UserPrincipalName =     $assignment.UserPrincipalName
                        Type         =          $assignment.Type
                        AccountEnabled    =     $assignment.AccountEnabled
                        UserType         =      $assignment.UserType
                        OnPremisesSyncEnabled = $assignment.OnPremisesSyncEnabled
                        JobTitle         =      $assignment.JobTitle
                        Department         =    $assignment.Department
                        AssignmentType     =    "Eligible"
                    }
                } elseif ($assignment.Type -eq "Group") {
                    $OwnerInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        DisplayName  = $assignment.DisplayName
                        Type         = $assignment.Type
                        SecurityEnabled         = $assignment.SecurityEnabled
                        IsAssignableToRole         = $assignment.IsAssignableToRole
                        AssignmentType     =    "Eligible"
                    }

                    #Match "parent" infos. Needed to link from eligible to parent groups
                    $ParentInfo = [PSCustomObject]@{
                        Id  = $assignment.groupId
                        DisplayName  = $GLOBALPimForGroupsHT[$assignment.groupId]
                        AssignmentType     =    "Eligible"
                    }
                    
                    # Store the object in the Parent Group hashtable by principalId used to lookup in which group a group has ownership of
                    if (-not $PimForGroupsEligibleOwnerParentGroupHT.ContainsKey($assignment.principalId)) {
                        $PimForGroupsEligibleOwnerParentGroupHT[$assignment.principalId] = @()  # Initialize as an empty array
                    }
                    $PimForGroupsEligibleOwnerParentGroupHT[$assignment.principalId] += $ParentInfo


                } else {
                    #This should never be triggered
                    $OwnerInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        DisplayName  = $assignment.DisplayName
                        Type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }
                }
        
                # Add the object to the array for that groupId
                $PimForGroupsEligibleOwnersHT[$assignment.groupId] += $OwnerInfo
            }
        }

        # Hashtable for all members for faster lookup in each group
        $PimForGroupsEligibleMembersHT = @{}
        $PimForGroupsEligibleMemberParentGroupHT = @{}
        foreach ($assignment in $TenantPimForGroupsAssignments) {
            if ($assignment.accessId -eq "member") {
                # Check if groupId already exists in the hashtable
                if (-not $PimForGroupsEligibleMembersHT.ContainsKey($assignment.groupId)) {
                    $PimForGroupsEligibleMembersHT[$assignment.groupId] = @()  # Initialize as an empty array
                }
                
                #Add Properties depending on the object type
                if ($assignment.Type -eq "User") {
                    $MemberInfo = [PSCustomObject]@{
                        Id  =                   $assignment.principalId
                        DisplayName  =          $assignment.DisplayName
                        UserPrincipalName =     $assignment.UserPrincipalName
                        Type         =          $assignment.Type
                        AccountEnabled    =     $assignment.AccountEnabled
                        UserType         =      $assignment.UserType
                        OnPremisesSyncEnabled = $assignment.OnPremisesSyncEnabled
                        JobTitle         =      $assignment.JobTitle
                        Department         =    $assignment.Department
                        AssignmentType     =    "Eligible"
                    }
                } elseif ($assignment.Type -eq "Group") {
                    $MemberInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        DisplayName  = $assignment.DisplayName
                        Type         = $assignment.Type
                        SecurityEnabled         = $assignment.SecurityEnabled
                        IsAssignableToRole         = $assignment.IsAssignableToRole
                        AssignmentType     =    "Eligible"
                    }
                    
                    #Match "parent" infos. Needed to link from eligible to parent groups
                    $ParentInfo = [PSCustomObject]@{
                        Id  = $assignment.groupId
                        DisplayName  = $GLOBALPimForGroupsHT[$assignment.groupId]
                        AssignmentType     =    "Eligible"
                    }

                    # Store the object in the Parent Group hashtable by principalId used to lookup in which group a group is nested in
                    if (-not $PimForGroupsEligibleMemberParentGroupHT.ContainsKey($assignment.principalId)) {
                        $PimForGroupsEligibleMemberParentGroupHT[$assignment.principalId] = @()  # Initialize as an empty array
                    }
                    $PimForGroupsEligibleMemberParentGroupHT[$assignment.principalId] += $ParentInfo

                } else {
                    #Fallback: This should never be triggered
                    $MemberInfo = [PSCustomObject]@{
                        Id  = $assignment.principalId
                        DisplayName  = $assignment.DisplayName
                        Type         = $assignment.Type
                        AssignmentType     =    "Eligible"
                    }
                }
        
                # Add the object to the array for that groupId
                $PimForGroupsEligibleMembersHT[$assignment.groupId] += $MemberInfo
 
            }
        }

    }

    ########################################## SECTION: DATACOLLECTION ##########################################

    Write-Host "[*] Get Groups"
    $QueryParameters = @{ 
        '$select' = 'Id,DisplayName,Visibility,GroupTypes,SecurityEnabled,IsAssignableToRole,OnPremisesSyncEnabled,MailEnabled,Description,MembershipRule' 
    }
    $AllGroups = Send-GraphRequest -AccessToken $GLOBALMsGraphAccessToken.access_token -Method GET -Uri '/groups' -QueryParameters $QueryParameters -BetaAPI -UserAgent $($GlobalAuditSummary.UserAgent.Name)

    $GroupsTotalCount = @($AllGroups).Count
    Write-Host "[+] Got $($GroupsTotalCount) groups"

    #Abort if no groups are present
    if (@($AllGroups).count -eq 0) {
        $AllGroupsDetailsHT = @{}
        Return $AllGroupsDetailsHT
    }
    
    ########################################## SECTION: Group Processing ##########################################

    #Build Hashtable with basic group info. Needed in nesting scenarios to git information about parent / child group
    $AllGroupsHT = @{}
    foreach ($group in $AllGroups) {
        $id = $group.id
        $securityEnabled = $group.securityEnabled
        $isAssignableToRole = if ($null -eq $group.isAssignableToRole) { $false } else { $group.isAssignableToRole }

        $AllGroupsHT[$id] = [PSCustomObject]@{
            securityEnabled     = $securityEnabled
            isAssignableToRole  = $isAssignableToRole
        }
    }

    # Check if Azure IAM roles were checked
    if (-not ($GLOBALAzurePsChecks)) {
        $GroupScriptWarningList += "Group Azure IAM assignments were not assessed"
    }

    #Check if CAP have been assessed
    if (-not ($GLOBALPermissionForCaps)) {
        $GroupScriptWarningList += "Group CAPs assignments were not assessed"
    }

    #Check if PIM for groups was checked
    if (-not ($GLOBALPimForGroupsChecked)) {
        $GroupScriptWarningList += "Pim for Groups was not assessed!"
    }

    Write-Host "[*] Get all group memberhips"
    #Get members of all groups for later lookup
    $Requests = @()
    $AllGroups | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/groups/$($_.id)/transitiveMembers"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $TransitiveMembersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $TransitiveMembersRaw[$item.id] = $item.response.value
        }
    }
    
    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all group ownerships"
    #Get owners of all groups for later lookup
    $Requests = @()
    $AllGroups | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/groups/$($_.id)/owners"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $GroupOwnersRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $GroupOwnersRaw[$item.id] = $item.response.value
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}

    Write-Host "[*] Get all group app role assignments"
    #Get group AppRole Assignments of all groups for later lookup
    $Requests = @()
    $AllGroups | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/groups/$($_.id)/appRoleAssignments"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $AppRoleAssignmentsRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $AppRoleAssignmentsRaw[$item.id] = $item.response.value
        }
    }

    #Check token validity to ensure it will not expire in the next 30 minutes
    if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
    
    Write-Host "[*] Get all group nestings"
    #Get groups which groups are nested in
    $Requests = @()
    $AllGroups | ForEach-Object {
        $Requests += @{
            "id"     = $($_.id)
            "method" = "GET"
            "url"    =   "/groups/$($_.id)/transitiveMemberOf/microsoft.graph.group"
        }
    }
    # Send Batch request and create a hashtable
    $RawResponse = (Send-GraphBatchRequest -AccessToken $GLOBALmsGraphAccessToken.access_token -Requests $Requests -beta -UserAgent $($GlobalAuditSummary.UserAgent.Name))
    $GroupNestedInRaw = @{}
    foreach ($item in $RawResponse) {
        if ($item.response.value -and $item.response.value.Count -gt 0) {
            $GroupNestedInRaw[$item.id] = $item.response.value
        }
    }

    #Calc dynamic update interval
    $StatusUpdateInterval = [Math]::Max([Math]::Floor($GroupsTotalCount / 10), 1)
    Write-Host "[*] Status: Processing group 1 of $GroupsTotalCount (updates every $StatusUpdateInterval groups)..."

    # Loop through each group and get additional info
    foreach ($group in $AllGroups) {

        #Loop init section
        $ProgressCounter++
        $ImpactScore = 0
        $LikelihoodScore = 0
        $Warnings = @()
        $ownerGroup = @()
        $PfGOwnedGroups = @()
        $GroupNestedIn = @()
        $AppRoleAssignments = @()
        $PimforGroupsEligibleOwners = New-Object System.Collections.ArrayList
        $PimforGroupsEligibleMembers = New-Object System.Collections.ArrayList
		$AzureRoleDetails = @()

        # Check the token lifetime after a specific amount of objects
        if (($ProgressCounter % $TokenCheckLimit) -eq 0 -and $SkipAutoRefresh -eq $false) {
            if (-not (Invoke-CheckTokenExpiration $GLOBALmsGraphAccessToken)) { RefreshAuthenticationMsGraph | Out-Null}
        }

        # Display status based on the objects numbers (slightly improves performance)
        if ($ProgressCounter % $StatusUpdateInterval -eq 0 -or $ProgressCounter -eq $GroupsTotalCount) {
            Write-Host "[*] Status: Processing group $ProgressCounter of $GroupsTotalCount..."
        }

        #Find parent groups if actual group
        if ($GroupNestedInRaw.ContainsKey($group.Id)) {
            foreach ($member in $GroupNestedInRaw[$group.Id]) {
                $isAssignableToRole = if ($null -eq $member.isAssignableToRole) { $false } else { $member.isAssignableToRole }
                $GroupNestedIn += [PSCustomObject]@{
                    Id              = $member.id
                    DisplayName     = $member.displayName
                    SecurityEnabled = $member.securityEnabled
                    isAssignableToRole = $isAssignableToRole
                    AssignmentType  = 'Active'
                    EntraRoles = 0 #Might be changed in post processing
                    AzureRoles = 0 #Might be changed in post processing
                    CAPs = 0 #Might be changed in post processing
                }
            }
        }
        
        #Check if group has an app role
        if ($AppRoleAssignmentsRaw.ContainsKey($group.Id)) {
            foreach ($AppRole in $AppRoleAssignmentsRaw[$group.Id]) {
                $AppRoleAssignments += [PSCustomObject]@{
                    ResourceDisplayName = $AppRole.ResourceDisplayName
                    ResourceId     = $AppRole.ResourceId
                    AppRoleId = $AppRole.AppRoleId
                }
            }
        }
        


		# Initialize ArrayLists
		$memberUser    	= [System.Collections.ArrayList]::new()
		$memberGroup   	= [System.Collections.ArrayList]::new()
		$memberSP      	= [System.Collections.ArrayList]::new()
		$memberDevices 	= [System.Collections.ArrayList]::new()
		$owneruser 		= [System.Collections.ArrayList]::new()
		$ownersp 		= [System.Collections.ArrayList]::new()

        # Process group members
        if ($TransitiveMembersRaw.ContainsKey($group.Id)) {
            foreach ($member in $TransitiveMembersRaw[$group.Id]) {
                switch ($member.'@odata.type') {
        
                    '#microsoft.graph.user' {
                        [void]$memberUser.Add(
                            [PSCustomObject]@{
                                Id                    = $member.Id
                                userPrincipalName     = $member.userPrincipalName
                                accountEnabled        = $member.accountEnabled
                                userType              = $member.userType
                                department            = $member.department
                                jobTitle              = $member.jobTitle
                                onPremisesSyncEnabled = $member.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }
        
                    '#microsoft.graph.group' {
                        $isAssignableToRole = if ($null -eq $member.isAssignableToRole) { $false } else { $member.isAssignableToRole }
                        [void]$memberGroup.Add(
                            [PSCustomObject]@{
                                Id                  = $member.Id
                                displayName         = $member.displayName
                                securityEnabled     = $member.securityEnabled
                                isAssignableToRole  = $isAssignableToRole
                                AssignmentType      = 'Active'
                            }
                        )
                    }
        
                    '#microsoft.graph.servicePrincipal' {
                        [void]$memberSP.Add(
                            [PSCustomObject]@{
                                Id                     = $member.Id
                                displayName            = $member.displayName
                                accountEnabled         = $member.accountEnabled
                                appOwnerOrganizationId = $member.appOwnerOrganizationId
                                publisherName          = $member.publisherName
                                servicePrincipalType   = $member.servicePrincipalType
                            }
                        )
                    }
        
                    '#microsoft.graph.device' {
                        [void]$memberDevices.Add(
                            [PSCustomObject]@{
                                Id                     = $member.Id
                                displayName            = $member.displayName
                                operatingSystem        = $member.operatingSystem
                                operatingSystemVersion = $member.operatingSystemVersion
                                profileType            = $member.profileType
                                accountEnabled         = $member.accountEnabled
                            }
                        )
                    }
                }
            }
        }

        #Process group owners
        if ($GroupOwnersRaw.ContainsKey($group.Id)) {
            foreach ($Owner in $GroupOwnersRaw[$group.Id]) {
                switch ($Owner.'@odata.type') {
        
                    '#microsoft.graph.user' {
                        [void]$owneruser.Add(
                            [PSCustomObject]@{
                                Id                    = $Owner.Id
                                userPrincipalName     = $Owner.userPrincipalName
                                accountEnabled        = $Owner.accountEnabled
                                userType              = $Owner.userType
                                department            = $Owner.department
                                jobTitle              = $Owner.jobTitle
                                onPremisesSyncEnabled = $Owner.onPremisesSyncEnabled
                                AssignmentType        = 'Active'
                            }
                        )
                    }
        
                    '#microsoft.graph.servicePrincipal' {
                        [void]$ownersp.Add(
                            [PSCustomObject]@{
                                Id                     = $Owner.Id
                                displayName            = $Owner.displayName
                                accountEnabled         = $Owner.accountEnabled
                                appOwnerOrganizationId = $Owner.appOwnerOrganizationId
                                publisherName          = $Owner.publisherName
                                servicePrincipalType   = $Owner.servicePrincipalType
                            }
                        )
                    }
        
                    default {
                        # Optional: log or handle unexpected owner types
                        Write-host "Unknown owner type: $($Owner.'@odata.type') for group $($group.Id)"
                    }
                }
            }
        }
        

       #Process pim for groups. Assignments will be added to the normal $memberGroup, $memberUser, $owneruser array and proccessed like active assignments
        if ($TenantPimForGroupsAssignments) {

            # Check if the group exists in the hashtable
            if ($PimForGroupsEligibleOwnersHT.ContainsKey($group.Id)) {
                # Retrieve all owners for this group
                $PfGownersGroup = @($PimForGroupsEligibleOwnersHT[$group.Id] | Where-Object { $_.type -eq "group" })
                $PfGownersUser = @($PimForGroupsEligibleOwnersHT[$group.Id] | Where-Object { $_.type -eq "user" })
                
                # Merge with normal owner list
                $owneruser = $owneruser + $PfGownersUser
                $ownerGroup = $PfGownersGroup
            }

            #Find groups where this group is an eligible owner
            if ($PimForGroupsEligibleOwnerParentGroupHT.ContainsKey($group.Id)) {
                $PfGOwnedGroupsRaw = @($PimForGroupsEligibleOwnerParentGroupHT[$group.Id])
                $PfGOwnedGroups = foreach ($OwnedGroup in $PfGOwnedGroupsRaw) {
                    #Get additonal proprties for the group
                    if ($AllGroupsHT.ContainsKey($group.Id)) {
                        $info = $AllGroupsHT[$OwnedGroup.Id]
                        [PSCustomObject]@{
                            Id                  = $OwnedGroup.Id
                            DisplayName         = $OwnedGroup.DisplayName
                            AssignmentType      = $OwnedGroup.AssignmentType
                            SecurityEnabled     = $info.SecurityEnabled
                            isAssignableToRole  = $info.isAssignableToRole
                            EntraRoles = 0 #Might be changed in post processing
                            AzureRoles = 0 #Might be changed in post processing
                            CAPs = 0 #Might be changed in post processing
                        }
                    }
                }
             }

            
            # Check if the group exists in the hashtable
            if ($PimForGroupsEligibleMembersHT.ContainsKey($group.Id)) {
                # Retrieve all members of the groups for this group
				 foreach ($pimMember in $PimForGroupsEligibleMembersHT[$group.Id]) {
					if ($pimMember.type -eq "group") { [void]$memberGroup.Add($pimMember) }
					elseif ($pimMember.type -eq "user") { [void]$memberUser.Add($pimMember) }
				}
            }

            #Find groups where this group is an eligible member
            if ($PimForGroupsEligibleMemberParentGroupHT.ContainsKey($group.Id)) {
                $PfGnestedGroupsRaw = @($PimForGroupsEligibleMemberParentGroupHT[$group.Id])
                $PfGnestedGroups = foreach ($ParentGroup in $PfGnestedGroupsRaw) {
                    #Get additonal proprties for the group
                    if ($AllGroupsHT.ContainsKey($group.Id)) {
                        $info = $AllGroupsHT[$ParentGroup.Id]
                        [PSCustomObject]@{
                            Id                  = $ParentGroup.Id
                            DisplayName         = $ParentGroup.DisplayName
                            AssignmentType      = $ParentGroup.AssignmentType
                            SecurityEnabled     = $info.SecurityEnabled
                            isAssignableToRole  = $info.isAssignableToRole
                            EntraRoles = 0 #Might be changed in post processing
                            AzureRoles = 0 #Might be changed in post processing
                            CAPs = 0 #Might be changed in post processing
                        }
                    }
                }
                
                # Merge with normal nested list
                $GroupNestedIn = $GroupNestedIn + $PfGnestedGroups 
            }       
        }

        # If PIM for Group has been evaluated: Check if group is onboarded in PIM for Groups
        $PIM = if (-not $GLOBALPimForGroupsChecked) {
            "?"
        } elseif ($GLOBALPimForGroupsHT -and $GLOBALPimForGroupsHT.ContainsKey($group.Id)) {
            $true
        } else {
            $false
        }
   

        #Count the owners to show in table
        $ownersynced = (@($owneruser | Where-Object { $_.onPremisesSyncEnabled -eq $true })).Count

        #check guest counts
        $GuestsCount = (@($memberUser | Where-Object { $_.UserType -eq "Guest" })).count

        #Get details for service principals
        $memberSpDetails = foreach ($object in $memberSP) {
            CheckSP $object
        }
        $ownerSpDetails = foreach ($object in $ownersp) {
            CheckSP $object
        }

        # Determine group type
        if ($group.GroupTypes -eq "Unified") {
            $groupType = "M365 Group"
            $ImpactScore += $GroupImpactScore["M365Group"]
        } elseif ($group.SecurityEnabled -eq $false -and $group.MailEnabled -eq $true) {
            $groupType = "Distribution"
            $ImpactScore += $GroupImpactScore["Distribution"]
        } else {
            $groupType = "Security Group"
        }

        # Check if dynamic
        if ($group.GroupTypes -eq "DynamicMembership") {
            $group | Add-Member -NotePropertyName Dynamic -NotePropertyValue $true
        } else {
            $group | Add-Member -NotePropertyName Dynamic -NotePropertyValue $false
        }

        # Add visibility default value if empty
        If ($null -eq $group.Visibility) {
            $group.Visibility = "Private"
        }

        # Add sync default value if empty
        If ($null -eq $group.OnPremisesSyncEnabled) {
            $group.OnPremisesSyncEnabled = $false
        }

        # For all security enabled groups check if there are Azure IAM assignments
        if ($GLOBALAzurePsChecks) {
            if ($group.SecurityEnabled -eq $true) {
                
                    #Use function to get the Azure Roles for each object
                    $azureRoleDetails = Get-AzureRoleDetails -AzureIAMAssignments $AzureIAMAssignments -ObjectId $group.Id

                    # Update the Roles property only if there are matching roles
                    $AzureRoleCount = @($azureRoleDetails).Count
                } else {
                $AzureRoleCount = 0
            }
        } else {
            $AzureRoleCount = "?"
        }



        # Check if the group is assignable to a role
        if ($group.IsAssignableToRole -eq $true) {

            # Find matching roles in $TenantRoleAssignments where the PrincipalId matches the group's Id
            $MatchingRoles = $TenantRoleAssignments[$group.Id]
            
            # Array to hold the role information for this group
            $roleDetails = @()

            foreach ($role in $MatchingRoles) {
                $roleInfo = [PSCustomObject]@{
                    DisplayName       = $role.DisplayName
                    Id                = $role.Id
                    AssignmentType    = $role.AssignmentType
                    IsPrivileged      = $role.IsPrivileged
                    RoleTier          = $role.RoleTier
                    IsEnabled         = $role.IsEnabled
                    IsBuiltIn         = $role.IsBuiltIn
                    DirectoryScopeId  = $role.DirectoryScopeId
                    ScopeResolved     = $role.ScopeResolved
                }
                # Add the role information to the RoleDetails array
                $roleDetails += $roleInfo
            }

            # Update the Roles property only if there are matching roles
            if (@($roleDetails).Count -gt 0) {
                $RoleCount = @($roleDetails).Count
                $RolePrivilegedCount = @($roleDetails | Where-Object { $_.IsPrivileged -eq $true }).Count
            }

        } else {
            $RoleCount = 0
            $RolePrivilegedCount  = 0
            $roleDetails = @()
            $group.IsAssignableToRole = $false
        }

        #Check AU assignment
        $GroupAdminUnits = $AdminUnitWithMembers | Where-Object { $_.MembersGroup.Id -contains $group.Id }
        if (@($GroupAdminUnits.IsMemberManagementRestricted) -contains $true) {
            $Warnings += "Group protected by restricted AU"
        }

        # Check if the script has permission to enumerate CAPs
        if ($GLOBALPermissionForCaps) {

            # Initialize a list to store CAP information for this group
            $groupCAPs = @()

            # Loop through each conditional access policy in $CapGroups
            foreach ($cap in $ConditionalAccessPolicies) {
                # Check if the group ID is in the ExcludedGroup or IncludedGroup of the CAP
                $isExcluded = $cap.ExcludedGroup -contains $group.Id
                $isIncluded = $cap.IncludedGroup -contains $group.Id

                if ($isExcluded -or $isIncluded) {

                    # Determine if the group is "Included" or "Excluded"
                    $groupUsage = if ($isExcluded) { "Excluded" } elseif ($isIncluded) { "Included" }

                    # Add CAP information to the list for this group
                    $groupCAPs += [PSCustomObject]@{
                        Id         = $cap.Id
                        CAPName    = $cap.CAPName
                        CAPExOrIn  = $groupUsage
                        CAPStatus  = $cap.CAPStatus
                    }
                }
            }

            # Add the CAP information to the group properties if any CAPs were found
            if (@($groupCAPs).Count -ge 1) {
                $CAPCount = @($groupCAPs).Count
            } else {
                $CAPCount = 0
                $groupCAPs = @()

            }
        } else {
            # If no permission for CAPs, set CAPCount to "?"
            $CAPCount = "?"
        }



    ########################################## SECTION: RISK RATING AND WARNINGS ##########################################
        if ($GLOBALAzurePsChecks -and $AzureRoleCount -ge 1) {

            #Use function to get the impact score and warning message for assigned Azure roles
            $AzureRolesProcessedDetails = Invoke-AzureRoleProcessing -RoleDetails $azureRoleDetails
            $Warnings += $AzureRolesProcessedDetails.Warning
            $ImpactScore += $AzureRolesProcessedDetails.ImpactScore
            $AzureRoleScore = $AzureRolesProcessedDetails.ImpactScore

            #Add group to list for re-processing
            if (@($memberGroup).count -ge 1) {
	            $NestedGroupsHighvalue += [pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group with AzureRole"
	                "AzureRoles" = $AzureRoleCount
	                "TargetGroups" = $memberGroup.Id
	            }
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue += [pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of with AzureRole"
                    "AzureRoles" = $AzureRoleCount
	                "Score" = $AzureRoleScore
	                "TargetGroups" = $ownerGroup.Id
	            }
            }
        }


        #Direct owner
        if (@($owneruser).count -ge 1) {

            #Check if there is an owner synced from on-prem
            if ($null -ne $owneruser.onPremisesSyncEnabled) {
                $LikelihoodScore += $GroupLikelihoodScore["DirectOwnerOnprem"]
            } else {
                $LikelihoodScore += $GroupLikelihoodScore["DirectOwnerCloud"]
            }
        }

        #PimForGroupsOwners
        if (@($ownerGroup).count -ge 1) {
            $LikelihoodScore += $GroupLikelihoodScore["PIMforGroupsOwnersGroup"]
        }

        #Process Entra Role assignments
        #Use function to get the impact score and warning message for assigned Entra roles
        if ($RoleCount -ge 1) {
            $EntraRolesProcessedDetails = Invoke-EntraRoleProcessing -RoleDetails $RoleDetails
            $Warnings += $EntraRolesProcessedDetails.Warning
            $ImpactScore += $EntraRolesProcessedDetails.ImpactScore
            $RoleScore = $EntraRolesProcessedDetails.ImpactScore
        }

        if ($RoleCount -ge 1) {
            #Add group to list for re-processing 
            if (@($memberGroup).count -ge 1) {
	            $NestedGroupsHighvalue += [pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group with EntraRole"
                    "EntraRoles" = $RoleCount
	                "Score" = $RoleScore
	                "TargetGroups" = $memberGroup.Id
	            }
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue += [pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of group with EntraRole"
                    "EntraRoles" = $RoleCount
	                "Score" = $RoleScore
	                "TargetGroups" = $ownerGroup.Id
	            }
            }
        }


        #Check if groups can be modified by low-tier admins or SPs
        if ($group.OnPremisesSyncEnabled -or $group.IsAssignableToRole -or @($GroupAdminUnits.IsMemberManagementRestricted) -contains $true) {
            $Protected = $true
        } else {
            $Protected = $false
            $LikelihoodScore += $GroupLikelihoodScore["BaseNotProtected"] #Group base score if not protected
        }


        #Check if assigned to Caps
        if ($CAPCount -ge 1) {
            $ImpactScore += $GroupImpactScore["CAP"]
            if ($group.IsAssignableToRole -eq $true) {
                $Warnings += "Group is used in CAP"
            } elseif ($group.Dynamic -eq $true) {
                $Warnings += "Group is used in CAP and is dynamic"
            } elseif ($group.OnPremisesSyncEnabled -eq $true) {
                $Warnings += "Group is used in CAP and from on-prem"
            } elseif ($group.Visibility -eq "Public" -and $groupDynamic -eq $false -and $grouptype -contains "M365 Group") {
                $Warnings += "Public M365 group in CAP"
            } elseif (-not $Protected) {
                $Warnings += "Group is used in CAP and is not protected"
            }

            #Add group to list for re-processing
            $score = $GroupImpactScore["CAP"]
            if (@($memberGroup).count -ge 1) {
	            $NestedGroupsHighvalue += [pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible member or nested in group used in CAP"
                    "CAPs" = $CAPCount
	                "Score" = $score
	                "TargetGroups" = $memberGroup.Id
	            }
            }
            if (@($ownerGroup).count -ge 1) {
	            $NestedGroupsHighvalue += [pscustomobject]@{
	                "Group" = $group.DisplayName
	                "GroupID" = $group.Id
	                "Message" = "Eligible owner of group used in CAP"
                    "CAPs" = $CAPCount
	                "Score" = $score
	                "TargetGroups" = $ownerGroup.Id
	            }
            }
            
        }

        #Check if M365 group is public
        if ($group.visibility -eq "Public" -and $grouptype -eq "M365 Group" -and $group.Dynamic -eq $false) {
            If ($group.SecurityEnabled) {
                $Warnings += "Public security enabled M365 group"
            } else {
                $Warnings += "Public M365 group"
            }

            $LikelihoodScore += $GroupLikelihoodScore["PublicM365Group"]

            if (@($AppRoleAssignments).count -ge 1) { 
                $Warnings += "Used for AppRoles"
            }       
        }

        #Check for guests as owner
        if ($owneruser.userType -contains "Guest") {
            $Warnings += "Guest as owner"
            $LikelihoodScore += $GroupLikelihoodScore["GuestMemberOwner"]
        }

        #Check if group is dynamic
        if ($group.Dynamic -eq $true) {
            if (@($AppRoleAssignments).count -ge 1) { 
                $ForAppRoles = " used for AppRoles"
            } else {
                $ForAppRoles = ""
            }

            #Search for potential dangerous queries
            if ($group.MembershipRule -match "user.userPrincipalName " -or $group.MembershipRule -match "user.otherMail " -or $group.MembershipRule -match "user.mail" -or $group.MembershipRule -match "user.PreferredLanguage" -or $group.MembershipRule -match "user.MobilePhone" -or $group.MembershipRule -match "user.BusinessPhones") {
                $DangerousQuery = "with potentially dangerous query"
                $LikelihoodScore += $GroupLikelihoodScore["DynamicGroupDangerous"]
            } else {
                $DangerousQuery = ""
                $LikelihoodScore += $GroupLikelihoodScore["DynamicGroup"]
            }
            $Warnings += "Dynamic group $DangerousQuery $ForAppRoles"
        }

        #Check app roles
        if (@($AppRoleAssignments).count -ge 1) {
            $ImpactScore += $GroupImpactScore["AppRole"]
        }

        #SP as member
        if (@($memberSP).count -ge 1) {
            if ($memberSpDetails.Foreign -contains $true -and $memberSpDetails.DefaultMS -contains $false) {
                $Warnings += "External (non-MS) SP as member"
                $LikelihoodScore += $GroupLikelihoodScore["ExternalSPMemberOwner"]
            } elseif ($memberSpDetails.Foreign -contains $false -and $memberSpDetails.DefaultMS -contains $false) {
                $Warnings += "Internal SP as member"
                $LikelihoodScore += $GroupLikelihoodScore["InternalSPMemberOwner"]
            } else {
                $LikelihoodScore += 1
            }
        }

        #SP as owner
        if (@($ownersp).count -ge 1) {
            if ($ownerSpDetails.Foreign -contains $true -and $ownerSpDetails.DefaultMS -contains $false) {
                $Warnings += "External (non-MS) SP as owner"
                $LikelihoodScore += $GroupLikelihoodScore["ExternalSPMemberOwner"]
            } elseif ($ownerSpDetails.Foreign -contains $false -and $ownerSpDetails.DefaultMS -contains $false) {
                $Warnings += "Internal SP as owner"
                $LikelihoodScore += $GroupLikelihoodScore["InternalSPMemberOwner"]
            }
        }

        #Has members
		$MemberUserCount = @($memberuser).count
        if ($MemberUserCount -ge 1) {
            $LikelihoodScore += $MemberUserCount * $GroupLikelihoodScore["Member"]
        }

        #Is security enabled and has any members/owners, is dynamic etc
        if ($group.SecurityEnabled) {
            $ImpactScore += $GroupImpactScore["SecurityEnabled"]
        }
        
        
        

        #Format warning messages
        $Warnings = if ($null -ne $Warnings) {
            $Warnings -join ' / '
        } else {
            ''
        }


        # Create custom object
        $groupDetails = [PSCustomObject]@{ 
            Id = $group.Id 
            DisplayName = $group.DisplayName
            DisplayNameLink = "<a href=#$($group.id)>$($group.DisplayName)</a>"
            Type = $groupType
            Visibility = $group.Visibility
            RoleAssignable = $group.IsAssignableToRole
            SecurityEnabled = $group.SecurityEnabled
            OnPrem = $group.OnPremisesSyncEnabled
            Description = $group.Description
            Dynamic = $group.dynamic
            MembershipRule = $group.MembershipRule
            EntraRoles  = $RoleCount
            EntraRolePrivilegedCount = $RolePrivilegedCount
            EntraRoleDetails = $roleDetails
            GroupCAPsDetails = $groupCAPs
            CAPs = $CAPCount
            AzureRoles = $AzureRoleCount
            AzureRoleDetails = $azureRoleDetails
            AppRoles = @($AppRoleAssignments).count
            AppRolesDetails = $AppRoleAssignments
            Users = $MemberUserCount
            Userdetails = $memberuser
            Guests = $GuestsCount
            PIM = $PIM
            NestedGroups = @($membergroup).count
            NestedGroupsDetails = $membergroup
            NestedInGroups = @($GroupNestedIn).count
            NestedInGroupsDetails = $GroupNestedIn
            PfGOwnedGroupsDetails = $PfGOwnedGroups
            AuUnits = @($GroupAdminUnits).count
            AuUnitsDetails = $GroupAdminUnits
            SPCount = @($memberSP).count
            MemberSpDetails = $memberSpDetails
            Devices = @($memberdevices).count
            DevicesDetails = $memberdevices
            DirectOwners = @($owneruser).count + @($ownersp).count + @($OwnerGroup).count
            NestedOwners = 0 #Will be adjusted in port-processing
            OwnerUserDetails = $owneruser
            OwnerGroupDetails = $OwnerGroup
            OwnersSynced = $ownersynced
            ownerSpDetails = $ownerSpDetails
            InheritedHighValue = 0
            Protected = $Protected
            NestedOwnerUserDetails = @()
            NestedOwnerSPDetails = @()
            Risk = [math]::Ceiling($ImpactScore * $LikelihoodScore)
            Impact = [math]::Round($ImpactScore,1)
            ImpactOrg = [math]::Round($ImpactScore) #Will be required in the user script
            Likelihood = [math]::Round($LikelihoodScore,1)
            Warnings = $Warnings
        }
		[void]$AllGroupsDetails.Add($groupDetails)
    }
    

    ########################################## SECTION: POST-PROCESSING ##########################################
    write-host "[*] Post-processing group nesting"

    # Reprocessing nested groups in groups which give access to potential critical ressources -> Nested group is adjusted
    # Note: Nested groups do not inherit AppRoles
    foreach ($highValueGroup in $NestedGroupsHighvalue) {

        # Split Targets into an array (in case of multiple IDs separated by commas)
        $targetIds = $highValueGroup.TargetGroups -split ','
        foreach ($targetId in $targetIds) {
            $counter = 0

            # Find matching groups in $AllGroupsDetails based on Id and Target ID
            foreach ($group in $AllGroupsDetails | Where-Object { $_.Id -eq $targetId.Trim() }) {
                $counter ++
                # Increment/Recalculate impact and risk score
                $group.Impact += [math]::Round($highValueGroup.Score,1)
                $group.Risk = [math]::Ceiling($group.Impact * $group.Likelihood)

                # Increase caps and role counts on the child group
                if ($highValueGroup.CAPs) {$group.CAPs += $highValueGroup.CAPs}
                if ($highValueGroup.EntraRoles) {$group.EntraRoles += $highValueGroup.EntraRoles}
                if ($highValueGroup.AzureRoles) {$group.AzureRoles += $highValueGroup.AzureRoles}

                #Adjust role and CAP counts in details for Owned groups in the child group
                foreach ($ownedGroup in $group.PfGOwnedGroupsDetails) {
                    if ($ownedGroup.id -eq $highValueGroup.GroupID ){
                        if ($highValueGroup.CAPs) {$ownedGroup.CAPs += $highValueGroup.CAPs}
                        if ($highValueGroup.EntraRoles) {$ownedGroup.EntraRoles += $highValueGroup.EntraRoles}
                        if ($highValueGroup.AzureRoles) {$ownedGroup.AzureRoles += $highValueGroup.AzureRoles}
                    }       
                }

                #Adjust role and CAP counts in details for nested in group object in the child group
                foreach ($parentGroup in $group.NestedInGroupsDetails) {
                    if ($parentGroup.id -eq $highValueGroup.GroupID ){
                        if ($highValueGroup.CAPs) {$parentGroup.CAPs += $highValueGroup.CAPs}
                        if ($highValueGroup.EntraRoles) {$parentGroup.EntraRoles += $highValueGroup.EntraRoles}
                        if ($highValueGroup.AzureRoles) {$parentGroup.AzureRoles += $highValueGroup.AzureRoles}
                    }       
                }

                # Append the Message to Warnings
                if ($group.Warnings -and $group.Warnings -notcontains $highValueGroup.Message) {
                    $group.Warnings += " / " + $highValueGroup.Message
                } elseif (-not $group.Warnings) {
                    $group.Warnings = $highValueGroup.Message
                }
                $group.InheritedHighValue = $counter
            }
            
        }
    }

    #Reprocessing groups which have a nested group to include their owners  -> Parent group is adjusted
    $GroupsWithNestings = $AllGroupsDetails | Where-Object { $_.NestedGroups -ge 1 } | select-object Id,Displayname,NestedGroupsDetails
    #$Group = $GroupsWithNestings | where-object id -eq "77ba9227-08d0-4d0a-9885-f52bbd3f1634"

    foreach ($Group in $GroupsWithNestings) {
        # $nestedGroup = $Group.NestedGroupsDetails
        foreach ($nestedGroup in $Group.NestedGroupsDetails) {

            # Matching group = nested group
            $matchingGroup = $AllGroupsDetails | Where-Object { $_.Id -eq $nestedGroup.Id }
            #Target group = parent group (will be adjusted)
            $targetGroup = $AllGroupsDetails | Where-Object { $_.Id -eq $Group.Id }

            #Detecting risky nesting
            if ($targetGroup.Protected -and -not $matchingGroup.Protected) {
                if ($targetGroup.Warnings -notcontains "Protected group has nested / is owned by unprotected group") {
                    $targetGroup.Warnings += " / Protected group has nested / is owned by unprotected group"  
                }
            }

            if ($matchingGroup -and $matchingGroup.DirectOwners -ge 1) {
                #Define target group (parent group will be adjusted not the nested group)
                
                #Checks for owners type users
                if (@($matchingGroup.OwnerUserDetails).count -ge 1) {
                    $OnPremOwnersCount = 0
                    $NestedOwnersCount = 0

                    # Append the new value to the array
                    $targetGroup.NestedOwnerUserDetails += $matchingGroup.OwnerUserDetails

                    # Count all owners and on-prem synced owners
                    $NestedOwnersCount = @($matchingGroup.OwnerUserDetails).count
                    $OnPremOwnersCount = @($matchingGroup.OwnerUserDetails | Where-Object { $_.onPremisesSyncEnabled -eq $true }).count

                    # Update counts in targetGroup properties
                    $targetGroup.NestedOwners += $NestedOwnersCount
                    $targetGroup.OwnersSynced += $OnPremOwnersCount
                }

                #Checks for owners type SP
                if (@($matchingGroup.ownerSpDetails).count -ge 1) {
                    #Add a property containing the nested owner (SP)      
                    $targetGroup.NestedOwnerSPDetails += $matchingGroup.OwnerSpDetails
                    $targetGroup.NestedOwners += @($matchingGroup.ownerSpDetails).count -ge 1
                }
            }
            #Takeover likelihood score from nested group and updated the risk
            if ($matchingGroup) {
                $targetGroup.Likelihood += [math]::Round($matchingGroup.Likelihood,1)
                $targetGroup.Risk = [math]::Ceiling($targetGroup.Likelihood * $targetGroup.Impact)
            }
        }

    }

    ########################################## SECTION: OUTPUT DEFINITION ##########################################

    write-host "[*] Generating reports"

    #Define output of the main table
    $tableOutput = $AllGroupsDetails | Sort-Object Risk -Descending | select-object DisplayName,DisplayNameLink,Type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings
    $AppendixDynamic = $AllGroupsDetails | Where-Object Dynamic -eq $true | select-object DisplayName,Description,type,SecurityEnabled,AzureRoles,CAPs,AppRoles,MembershipRule,Warnings
    $DynamicGroupsCount = @($AppendixDynamic).count

    $mainTable = $tableOutput | select-object -Property @{Name = "DisplayName"; Expression = { $_.DisplayNameLink}},type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings
    $mainTableJson  = $mainTable | ConvertTo-Json -Depth 5 -Compress

    $mainTableHTML = $GLOBALMainTableDetailsHEAD + "`n" + $mainTableJson + "`n" + '</script>'


    #Define the apps to be displayed in detail and sort them by risk score
    $details = $AllGroupsDetails | Sort-Object Risk -Descending

    #Define stringbuilder to avoid performance impact
    $DetailTxtBuilder = [System.Text.StringBuilder]::new()


    foreach ($item in $details) {
        $ReportingAU = @()
        $ReportingRoles = @()
        $ReportingAzureRoles = @()
        $ReportingCAPs = @()
        $AppRoles = @()
        $OwnerUser = @()
        $OwnerGroups = @()
        $OwnerSP = @()
        $NestedOwnerUser = @()
        $NestedOwnerSP = @()
        $NestedGroups = @()
        $NestedUsers = @()
        $NestedSP = @()
        $NestedDevices = @()
        $NestedInGroups = @()
        $OwnedGroups = @()

        [void]$DetailTxtBuilder.AppendLine("#" * 120)

        ############### HEADER
        $ReportingGroupInfo = [pscustomobject]@{
            "Group Name" = $($item.DisplayName)
            "Group ObjectID" = $($item.Id)
            "Type" = $($item.Type)
            "SecurityEnabled" = $($item.SecurityEnabled)
            "Protected" = $($item.Protected)
            "Synced from on-prem" = $($item.OnPrem)
            "RiskScore" = $($item.Risk)
        }
        if ($item.Dynamic) {
            $ReportingGroupInfo | Add-Member -NotePropertyName DynamicRule -NotePropertyValue $item.MembershipRule
        }
        
        if ($item.Warnings -ne '') {
            $ReportingGroupInfo | Add-Member -NotePropertyName Warnings -NotePropertyValue $item.Warnings
        }

        [void]$DetailTxtBuilder.AppendLine(($ReportingGroupInfo | Out-String))
        
        ############### Administrative Units
        if (@($item.AuUnitsDetails).count -ge 1) {
            $ReportingAU = foreach ($object in $($item.AuUnitsDetails)) {
                [pscustomobject]@{ 
                    "Administrative Unit" = $($object.Displayname)
                    "IsMemberManagementRestricted" = $($object.IsMemberManagementRestricted)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Administrative Units")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAU | Out-String))
        }

        ############### Entra Roles
        if (@($item.EntraRoleDetails).count -ge 1) {
            $ReportingRoles = foreach ($object in $($item.EntraRoleDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $($object.DisplayName)
                    "Assignment" = $($object.AssignmentType)
                    "Tier Level" = $($object.RoleTier)
                    "Privileged" = $($object.isPrivileged)
                    "Builtin" = $($object.IsBuiltin)
                    "Scoped to" = "$($object.ScopeResolved.DisplayName) ($($object.ScopeResolved.Type)) "
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Entra Role Assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingRoles | Out-String))
        }

        ############### Azure Roles
        if (@($item.AzureRoleDetails).count -ge 1) {
            $ReportingAzureRoles = foreach ($role in $($item.AzureRoleDetails)) {
                [pscustomobject]@{ 
                    "Role name" = $($role.RoleName)
                    "Assignment" = $($role.AssignmentType)
                    "RoleType" = $($object.RoleType)
                    "Tier Level" = $($role.RoleTier)
                    "Conditions" = $($role.Conditions)
                    "Scoped to" = $($role.Scope)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Azure IAM assignments")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingAzureRoles | Out-String))
        } 

        ############### CAPs
        if (@($item.GroupCAPsDetails).count -ge 1) {
            $ReportingCAPs = foreach ($object in $($item.GroupCAPsDetails)) {
                [pscustomobject]@{
                    "CAPName" = $($object.CAPName)
                    "CAPNameLink" = "<a href=ConditionalAccessPolicies_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.Id)>$($object.CAPName)</a>"
                    "Usage" = $($object.CAPExOrIn)
                    "Status" = $($object.CAPStatus)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Linked Conditional Access Policies")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($ReportingCAPs | format-table -Property CAPName,Usage,Status | Out-String))
            #Rebuild for HTML report
            $ReportingCAPs = foreach ($obj in $ReportingCAPs) {
                [pscustomobject]@{
                    CAPName        = $obj.CAPNameLink
                    Usage          = $obj.Usage
                    Status         = $obj.Status
                }
            }
        }

        ############### App Roles
        if (@($item.AppRolesDetails).count -ge 1) {
            $AppRoles = foreach ($object in $($item.AppRolesDetails)) {
                [pscustomobject]@{ 
                    "UsedIn" = $($object.ResourceDisplayName)
                    "UsedInLink" = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.ResourceId)>$($object.ResourceDisplayName)</a>"
                    "AppRoleId" = $($object.AppRoleId)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("App Roles")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($AppRoles | format-table -Property UsedIn,AppRoleId | Out-String))
            
            #Rebuild for HTML report
            $AppRoles = foreach ($obj in $AppRoles) {
                [pscustomobject]@{
                    UsedInApp           = $obj.UsedInLink
                    AppRoleId           = $obj.AppRoleId
                }
            }
        }

        ############### Owners (Users)
        if (@($item.OwnerUserDetails).count -ge 1) {
            $OwnerUser = foreach ($object in $($item.OwnerUserDetails)) {
                if ($null -eq $object.department) {
                    $object.department = "-"
                }
                if ($null -eq $object.jobTitle) {
                    $object.jobTitle = "-"
                }
                if ($null -eq $object.onPremisesSyncEnabled) {
                    $object.onPremisesSyncEnabled = "False"
                }
                [pscustomobject]@{ 
                    "AssignmentType" = $($object.AssignmentType)
                    "Username" = $($object.userPrincipalName)
                    "UsernameLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.userPrincipalName)</a>"
                    "Enabled" = $($object.accountEnabled)
                    "Type" = $($object.userType)
                    "Synced" = $($object.onPremisesSyncEnabled)
                    "Department" = $($object.department)
                    "JobTitle" = $($object.jobTitle)
                }
            }
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Direct Owners (Users)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($OwnerUser | format-table -Property AssignmentType,Username,Enabled,Type,Synced,Department,JobTitle  | Out-String))

            #Rebuild for HTML report
            $OwnerUser  = foreach ($obj in $OwnerUser) {
                [pscustomobject]@{
                    AssignmentType  = $obj.AssignmentType
                    Username        = $obj.UsernameLink
                    Enabled         = $obj.Enabled
                    Type            = $obj.Type
                    Synced          = $obj.Synced
                    Department      = $obj.Department
                    JobTitle        = $obj.JobTitle
                }
            }
        }

        ############### Owners (Groups) (only possible with PIM for Groups)
        if (@($item.OwnerGroupDetails).count -ge 1) {
            $OwnerGroups = foreach ($object in $($item.OwnerGroupDetails)) {
                  [pscustomobject]@{ 
                    "AssignmentType" = $($object.AssignmentType)
                    "Displayname" = $($object.displayName)
                    "DisplayNameLink" = "<a href=#$($object.id)>$($object.displayName)</a>"
                    "SecurityEnabled" = $($object.SecurityEnabled)
                    "IsAssignableToRole" = $($object.IsAssignableToRole)
                }
            }
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Eligible Owners (Groups)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($OwnerGroups | format-table -Property AssignmentType,Displayname,SecurityEnabled,IsAssignableToRole | Out-String))

            #Rebuild for HTML report
            $OwnerGroups = foreach ($obj in $OwnerGroups) {
                [pscustomobject]@{
                    AssignmentType      = $obj.AssignmentType
                    DisplayName         = $obj.DisplayNameLink
                    SecurityEnabled     = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                }
            }
        }

        ############### Owners (SP)
        if (@($item.ownerSpDetails).count -ge 1) {
            $OwnerSP = foreach ($object in $($item.ownerSpDetails)) {
                [pscustomobject]@{ 
                    "DisplayName" = $($object.displayName)
                    "DisplayNameLink" = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.displayName)</a>"
                    "Type" = $($object.SPType)
                    "Org" = $($object.publisherName)
                    "Foreign" = $($object.Foreign)
                    "DefaultMS" = $($object.DefaultMS)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Direct Owners (Service Principals)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($OwnerSP | format-table -Property DisplayName,Type,Org,Foreign,DefaultMS | Out-String))

            #Rebuild for HTML report
            $OwnerSP = foreach ($obj in $OwnerSP) {
                [pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    Type          = $obj.Type
                    Organization  = $obj.Org
                    Foreign       = $obj.Foreign
                    DefaultMS     = $obj.DefaultMS
                }
            }
        }

        ############### Nested Owners (Users)
        if (@($item.NestedOwnerUserDetails).count -ge 1) {
            $NestedOwnerUser = foreach ($object in $($item.NestedOwnerUserDetails)) {
                if ($null -eq $object.department) {
                    $object.department = "-"
                }
                if ($null -eq $object.jobTitle) {
                    $object.jobTitle = "-"
                }
                if ($null -eq $object.onPremisesSyncEnabled) {
                    $object.onPremisesSyncEnabled = "False"
                }
                [pscustomobject]@{
                    "AssignmentType" = $($object.AssignmentType)
                    "Username" = $($object.userPrincipalName)
                    "UsernameLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.userPrincipalName)</a>"
                    "Enabled" = $($object.accountEnabled)
                    "Type" = $($object.userType)
                    "Synced" = $($object.onPremisesSyncEnabled)
                    "Department" = $($object.department)
                    "JobTitle" = $($object.jobTitle)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Owners (Users)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedOwnerUser | format-table -Property AssignmentType,Username,Enabled,Type,Synced,Department,JobTitle | Out-String))

            #Rebuild for HTML report
            $NestedOwnerUser  = foreach ($obj in $NestedOwnerUser) {
                [pscustomobject]@{
                    AssignmentType  = $obj.AssignmentType
                    Username        = $obj.UsernameLink
                    Enabled         = $obj.Enabled
                    Type            = $obj.Type
                    Synced          = $obj.Synced
                    Department      = $obj.Department
                    JobTitle        = $obj.JobTitle
                }
            }
        }

        ############### Nested Owners (SP)
        if (@($item.NestedOwnerSPDetails).count -ge 1) {
            $NestedOwnerSP = foreach ($object in $($item.NestedOwnerSPDetails)) {
                [pscustomobject]@{ 
                    "Displayname" = $($object.displayName)
                    "Type" = $($object.SPType)
                    "Org" = $($object.publisherName)
                    "Foreign" = $($object.Foreign)
                    "DefaultMS" = $($object.DefaultMS)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Owners (Service Principals)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedOwnerSP | format-table | Out-String))
        }

        ############### Nested Groups
        if (@($item.NestedGroupsDetails).count -ge 1) {
            $NestedGroups = foreach ($object in $($item.NestedGroupsDetails)) {
                [pscustomobject]@{ 
                    "AssignmentType" = $($object.AssignmentType)
                    "Displayname" = $($object.displayName)
                    "DisplayNameLink" = "<a href=#$($object.id)>$($object.displayName)</a>"
                    "SecurityEnabled" = $($object.SecurityEnabled)
                    "isAssignableToRole" = $($object.isAssignableToRole)
                }
            }


            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Members: Nested Groups")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedGroups | format-table -Property AssignmentType,Displayname, SecurityEnabled,isAssignableToRole | Out-String))

            #Rebuild for HTML report
            $NestedGroups = foreach ($obj in $NestedGroups) {
                [pscustomobject]@{
                    AssignmentType      = $obj.AssignmentType
                    DisplayName         = $obj.DisplayNameLink
                    SecurityEnabled     = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                }
            }
        }


        ############### Nested Users
        if (@($item.UserDetails).count -ge 1) {
            $NestedUsers = foreach ($object in $($item.UserDetails)) {
                if ($null -eq $object.department) {
                    $object.department = "-"
                }
                if ($null -eq $object.jobTitle) {
                    $object.jobTitle = "-"
                }
                if ($null -eq $object.onPremisesSyncEnabled) {
                    $object.onPremisesSyncEnabled = "False"
                }
                [pscustomobject]@{ 
                    "AssignmentType" = $($object.AssignmentType)
                    "Username" = $($object.userPrincipalName)
                    "UsernameLink" = "<a href=Users_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.userPrincipalName)</a>"
                    "Enabled" = $($object.accountEnabled)
                    "Type" = $($object.userType)
                    "Synced" = $($object.onPremisesSyncEnabled)
                    "Department" = $($object.department)
                    "JobTitle" = $($object.jobTitle)
                }
            }
            
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Members: Users")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedUsers | format-table -Property AssignmentType,Username,Enabled,Type,Synced,Department,JobTitle | Out-String))
            
            #Rebuild for HTML report
            $ObjectCounter = 0
            $NestedUsers  = foreach ($obj in $NestedUsers) {
                $ObjectCounter++
                if ($ObjectCounter -ge $HTMLMemberLimit) {
                    [pscustomobject]@{ 
                        "AssignmentType" = "-"
                        "Username" = "List limited to $HTMLMemberLimit users. See TXT Report for full list"
                        "Enabled" = "-"
                        "Type" = "-"
                        "Synced" = "-"
                        "Department" = "-"
                        "JobTitle" = "-"
                    }
                    break
                } else {
                    [pscustomobject]@{
                        AssignmentType  = $obj.AssignmentType
                        Username        = $obj.UsernameLink
                        Enabled         = $obj.Enabled
                        Type            = $obj.Type
                        Synced          = $obj.Synced
                        Department      = $obj.Department
                        JobTitle        = $obj.JobTitle
                    }
                }
            }
        }

        ############### Nested SP
        if (@($item.MemberSpDetails).count -ge 1) {
            $NestedSP = foreach ($object in $($item.MemberSpDetails)) {
                if ($($object.SPType) -eq "Application") {
                    $DisplayNameLink = "<a href=EnterpriseApps_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.displayName)</a>"
                    $org = $($object.publisherName)
                } else {
                    $DisplayNameLink = "<a href=ManagedIdentities_$($StartTimestamp)_$([System.Uri]::EscapeDataString($CurrentTenant.DisplayName)).html#$($object.id)>$($object.displayName)</a>"
                    $org = "-"
                }

                [pscustomobject]@{ 
                    "Displayname" = $($object.displayName)
                    "DisplayNameLink" = $DisplayNameLink 
                    "Type" = $($object.SPType)
                    "Org" = $org
                    "Foreign" = $($object.Foreign)
                    "DefaultMS" = $($object.DefaultMS)
                }
            }
  
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Members: Service Principals")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedSP | format-table -Property DisplayName,Type,Org,Foreign,DefaultMS  | Out-String))

            #Rebuild for HTML report
            $NestedSP = foreach ($obj in $NestedSP) {
                [pscustomobject]@{
                    DisplayName   = $obj.DisplayNameLink
                    Type          = $obj.Type
                    Organization  = $obj.Org
                    Foreign       = $obj.Foreign
                    DefaultMS     = $obj.DefaultMS
                }
            }
        }

        ############### Nested Devices
        if (@($item.DevicesDetails).count -ge 1) {
            $NestedDevices = foreach ($object in $($item.DevicesDetails)) {
                [pscustomobject]@{ 
                    "Displayname" = $($object.displayName)
                    "Enabled" = $($object.accountEnabled)
                    "Type" = $($object.profileType)
                    "OS" = "$($object.operatingSystem) / $($object.operatingSystemVersion)"
                }
            }
        
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Nested Members: Devices")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedDevices | format-table | Out-String))
            #Rebuild for HTML report
            $ObjectCounter = 0
            $NestedDevices  = foreach ($obj in $NestedDevices) {
                $ObjectCounter++
                if ($ObjectCounter -ge $HTMLMemberLimit) {
                    [pscustomobject]@{ 
                        "Displayname" = "List limited to $HTMLMemberLimit users. See TXT Report for full list"
                        "Enabled" = "-"
                        "Type" = "-"
                        "OS" = "-"
                    }
                    break
                } else {
                    [pscustomobject]@{
                        "Displayname"   = $obj.Displayname
                        "Enabled"       = $obj.Enabled
                        "Type"          = $obj.Type
                        "OS"            = $obj.OS
                    }
                }
            }
            
        }

        ############### Nested in Groups
        if (@($item.NestedInGroupsDetails).count -ge 1) {
            $NestedInGroups = foreach ($object in $($item.NestedInGroupsDetails)) {
                [pscustomobject]@{ 
                    "AssignmentType"    = $($object.AssignmentType)
                    "Displayname"       = $($object.displayName)
                    "DisplayNameLink"   = "<a href=#$($object.id)>$($object.displayName)</a>"
                    "SecurityEnabled"   = $($object.SecurityEnabled)
                    "IsAssignableToRole"= $($object.IsAssignableToRole)
                    "EntraRoles" =  $($object.EntraRoles)
                    "AzureRoles" =  $($object.AzureRoles)
                    "CAPs" =  $($object.CAPs)
                }
            }
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Member Of: Nested in Groups (Transitive)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($NestedInGroups | format-table -Property AssignmentType, Displayname, SecurityEnabled,IsAssignableToRole,EntraRoles,AzureRoles,CAPs | Out-String))
            #Rebuild for HTML report
            $NestedInGroups = foreach ($obj in $NestedInGroups) {
                [pscustomobject]@{
                    AssignmentType      = $obj.AssignmentType
                    DisplayName         = $obj.DisplayNameLink
                    SecurityEnabled     = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                    EntraRoles  = $obj.EntraRoles
                    AzureRoles  = $obj.AzureRoles
                    CAPs  = $obj.CAPs
                }
            }
        }


        ############### Owns another Group (Pim fro Groups)
        if (@($item.PfGOwnedGroupsDetails).count -ge 1) {
            $OwnedGroups = foreach ($object in $($item.PfGOwnedGroupsDetails)) {
                [pscustomobject]@{ 
                    "AssignmentType" = $($object.AssignmentType)
                    "Displayname" = $($object.displayName)
                    "DisplayNameLink" = "<a href=#$($object.id)>$($object.displayName)</a>"
                    "SecurityEnabled" = $($object.SecurityEnabled)
                    "IsAssignableToRole" = $($object.IsAssignableToRole)
                    "EntraRoles" =  $($object.EntraRoles)
                    "AzureRoles" =  $($object.AzureRoles)
                    "CAPs" =  $($object.CAPs)
                }
            }

            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine("Owned Groups (PIM for Groups)")
            [void]$DetailTxtBuilder.AppendLine("================================================================================================")
            [void]$DetailTxtBuilder.AppendLine(($OwnedGroups | format-table -Property AssignmentType, Displayname, SecurityEnabled,IsAssignableToRole,EntraRoles,AzureRoles,CAPs | Out-String))

            #Rebuild for HTML report
            $OwnedGroups = foreach ($obj in $OwnedGroups) {
                [pscustomobject]@{
                    AssignmentType   = $obj.AssignmentType
                    DisplayName      = $obj.DisplayNameLink
                    SecurityEnabled  = $obj.SecurityEnabled
                    IsAssignableToRole  = $obj.IsAssignableToRole
                    EntraRoles  = $obj.EntraRoles
                    AzureRoles  = $obj.AzureRoles
                    CAPs  = $obj.CAPs
                }
            }
        }
        
        $ObjectDetails = [pscustomobject]@{
            "Object Name"     = $item.DisplayName
            "Object ID"       = $item.Id
            "General Information"    = $ReportingGroupInfo
            "Administrative Units" = $ReportingAU
            "Entra ID Roles" = $ReportingRoles
            "Azure Roles" = $ReportingAzureRoles
            "Conditional Access Policies" = $ReportingCAPs
            "Application Roles" = $AppRoles
            "Owners (User)" = $OwnerUser
            "Owners (Groups)" = $OwnerGroups
            "Owners (SP)" = $OwnerSP
            "Nested owners (User)" = $NestedOwnerUser
            "Nested owner (SP)" = $NestedOwnerSP
            "Nested Groups" = $NestedGroups
            "Nested Users" = $NestedUsers
            "Nested SP" = $NestedSP 
            "Nested Devices " = $NestedDevices 
            "Nested in Groups " = $NestedInGroups
            "Owned Groups (PIM for Groups)" = $OwnedGroups
        }
    
        [void]$AllObjectDetailsHTML.Add($ObjectDetails)

    }

    $DetailOutputTxt = $DetailTxtBuilder.ToString()

    write-host "[+] Writing log files"
    write-host ""

    #Define header HTML
    $headerHTML = [pscustomobject]@{ 
        "Executed in Tenant" = "$($CurrentTenant.DisplayName) / ID: $($CurrentTenant.id)"
        "Executed at" = "$StartTimestamp "
        "Execution Warnings" = $GroupScriptWarningList -join ' / '
    }

# Build Detail section as JSON for the HTML Report
$AllObjectDetailsHTML = $AllObjectDetailsHTML | ConvertTo-Json -Depth 5 -Compress
$ObjectsDetailsHEAD = @'
    <h2>Groups Details</h2>
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
Execution Warnings = $($GroupScriptWarningList  -join ' / ')
************************************************************************************************************************
"

    #Define Appendix
$AppendixTitle = "

###############################################################################################################################################
Appendix: Dynamic Groups
###############################################################################################################################################
    "


    # Prepare HTML output
    $headerHTML = $headerHTML | ConvertTo-Html -Fragment -PreContent "<div id=`"loadingOverlay`"><div class=`"spinner`"></div><div class=`"loading-text`">Loading data...</div></div><nav id=`"topNav`"></nav><h1>$($Title) Enumeration</h1>" -As List -PostContent "<h2>$($Title) Overview</h2>"



    ########################################## SECTION: OUTPUT WRITING ##########################################

    #Write TXT and CSV files
    $headerTXT | Out-File -Width 512 -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput  |  Format-table DisplayName,type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings | Out-File -Width 512 "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
    $tableOutput | select-object DisplayName,type,SecurityEnabled,RoleAssignable,OnPrem,Dynamic,Visibility,Protected,PIM,AuUnits,DirectOwners,NestedOwners,OwnersSynced,Users,Guests,SPCount,Devices,NestedGroups,NestedInGroups,AppRoles,CAPs,EntraRoles,AzureRoles,Impact,Likelihood,Risk,Warnings | Export-Csv -Path "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).csv" -NoTypeInformation
    $DetailOutputTxt | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append

    write-host "[+] Details of $GroupsTotalCount groups stored in output files (CSV,TXT,HTML): $outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName)"
    If ($DynamicGroupsCount -gt 0) {
        $AppendixTitle | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppendixDynamic | Out-File -FilePath "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).txt" -Append
        $AppendixDynamicHTML = $AppendixDynamic | ConvertTo-Html -Fragment -PreContent "<h2>Appendix: Dynamic Groups</h2>"
    }

    $PostContentCombined = $GLOBALJavaScript + "`n" + $AppendixDynamicHTML
    #Write HTML
    $Report = ConvertTo-HTML -Body "$headerHTML $mainTableHTML" -Title "$Title enumeration" -Head $GLOBALcss -PostContent $PostContentCombined -PreContent $AllObjectDetailsHTML
    $Report | Out-File "$outputFolder\$($Title)_$($StartTimestamp)_$($CurrentTenant.DisplayName).html"

    Remove-Variable Report
    Remove-Variable DetailOutputTxt

    #Add information to the enumeration summary
    $M365Count = 0
    $OnPremCount = 0
    $PublicM365 = 0
    $PimOnboarded = 0

    foreach ($group in $AllGroupsDetails) {
        if ($group.Type -eq "M365 Group") {
            $M365Count++
            if ($group.Visibility -eq "Public") {
                $PublicM365++
            }
        }
        if ($group.OnPrem) {
            $OnPremCount++
        }
        if ($group.PIM -eq $true) {
            $PimOnboarded++
        }       
    }

    # Store in global var
    $GlobalAuditSummary.Groups.Count = $GroupsTotalCount
    $GlobalAuditSummary.Groups.M365 = $M365Count
    $GlobalAuditSummary.Groups.PublicM365 = $PublicM365
    $GlobalAuditSummary.Groups.OnPrem = $OnPremCount
    $GlobalAuditSummary.Groups.PimOnboarded = $PimOnboarded



    #Convert to Hashtable for faster searches
    $AllGroupsDetailsHT = @{}
    foreach ($group in $AllGroupsDetails) {
        $AllGroupsDetailsHT[$group.Id] = $group
    }
    Return $AllGroupsDetailsHT
}
