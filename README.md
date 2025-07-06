# EntraFalcon

MODIFIED:
Run it with:

```
> .\run_EntraFalcon.ps1 -SkipPimForGroups -Top 100 -Tenant <TENANT_ID> -Verbose
``` 

![alt text](/images/EntraFalcon_logo.png)

EntraFalcon is a PowerShell-based assessment tool for pentesters, security analysts, and system administrators to evaluate the security posture of a Microsoft Entra ID environment.

Designed for ease of use, EntraFalcon runs on PowerShell 5.1 and 7, supports both Windows and Linux, and requires no external dependencies or Microsoft Graph API consent.

The tool helps uncover privileged objects, potentially risky assignments and Conditional Access misconfigurations that are often overlooked, such as:
- Users with control over high-privilege groups or applications
- External or internal enterprise applications with excessive permissions (e.g., Microsoft Graph API, Azure roles)
- Users with Azure IAM role assignments directly on resources
- Privileged accounts synced from on-premises
- Inactive users or users without MFA capability
- Unprotected groups used in sensitive assignments (e.g., Conditional Access exclusions, Subscription Owner, or eligible member of a privileged group)

Findings are presented in interactive HTML reports to support efficient exploration and analysis.


## 🚀 Features

- Simple PowerShell script compatible with PowerShell 5.1 and 7. Works on both Windows and Linux with no external dependencies.
- Built-in authentication supporting multiple methods (Interactive Authorization Code Flow and Device Code flow)
- Uses first-party Microsoft applications with pre-consented scopes to bypass Graph API consent prompts
- Generates navigable HTML reports that support filtering, sorting, data export, etc.
- Performs basic impact, likelihood, and risk scoring to highlight weakly protected high-privilege objects and sort the data.
- Displays warnings for risky configurations and elevated privileges
- Enumerates Entra ID objects, including:
    - Users
    - Groups
    - Enterprise Applications
    - App Registrations
    - Managed Identities
    - PIM assignments:
        - PIM for Entra Roles
        - PIM for Entra Groups
        - PIM for Azure Roles
    - Entra Role Assignments
    - Azure Role Assignments
    - Conditional Access Policies
    - Administrative Units


## ✅ Requirements

|Type|Permission|Mandatory|Impact if missing|
|-|-|-|-|
|Entra ID Role|Global Reader|Yes|Not possible to run the scripts|
|Azure Role|Reader: On every Management Group or Subscription|No|Can't assess Azure IAM assignments|

Furthermore, you must be able to authenticate to the Microsoft Graph API and optionally the Azure ARM API from the device where you run the tool.
Ensure that Conditional Access Policies do not block your authentication.

## ▶️ Usage

The tool includes built-in support for Entra ID authentication using a custom forked PowerShell module.
You can choose from multiple authentication flows depending on your environment and preference.

> ⚠️ **Note:** Two separate authentications are required.  
> This is due to the need for a special first-party client with elevated scopes to access **PIM for Groups** data.  
> You can skip the enumeration of PIM for Groups (and thus the first authentication) by using the `-SkipPimForGroups` switch.

### Auth Code Flow (default) (Windows only)

```powershell
.\run_EntraFalcon.ps1
```

### Use Device Code Authentication

```powershell
.\run_EntraFalcon.ps1 -AuthMethod "DeviceCode"
```

### Use Manual Code Flow Authentication

```powershell
.\run_EntraFalcon.ps1 -AuthMethod "ManualCode"
```
1. Run the script — it will copy the authentication URL to your clipboard.
2. Paste the URL into a browser (can be done on a different device for SSO support).
3. Complete the authentication.
4. Copy the final redirect URL (containing the authorization code) to your clipboard.
5. Continue the script, which will automatically read the code from your clipboard and proceed with token acquisition.


### Include Microsoft-Owned Enterprise Apps
By default, official Microsoft enterprise applications are excluded from the assessment to reduce noise. To include them in the enumeration and analysis, use the `-IncludeMsApps` switch:
```powershell
.\run_EntraFalcon.ps1 -IncludeMsApps
```

### Skip PIM for Groups Assessment
Use the `-SkipPimForGroups` switch to skip the enumeration of PIM assignments for groups.  
This skips the additional authentication needed to access PIM for Groups data.
```powershell
.\run_EntraFalcon.ps1 -SkipPimForGroups
```

**Other Optional Parameters:**
| Parameter              | Description                                                                                                                      | Default Value                                     |
|----------------------  |----------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| **UserAgent**          | User agent used for the requests to the token endpoint and API calls.                                                            | `EntraFalcon`                                     |  
| **DisableCAE**         | Disables requesting Continuous Access Evaluation (CAE) tokens.                                                                   | `false`                                           |
| **Tenant**             | Specifies the tenant (ID or domain) to authenticate against. Useful when assessing a tenant other than the account’s home tenant.|`Account's home tenant`                            |
| **OutputFolder**       | Output folder where the reports are stored.                                                                                      |`Results_%TenantName%_YYYYMMDD_HHSS`               |
| **LimitResults**       | Limits the number of groups and users in the report (after sorting by risk). Useful for large tenants.                           | -                                                 |
| **Verbose**            | Enables detailed output. Useful for troubleshooting and monitoring progress in large tenants.                                    | -                                                 |


## 📊 Example Reports

**Users**  
![alt text](/images/user.png)

**Azure Roles**  
![alt text](/images/azure_roles.png)

**Enterprise Application Details**  
![alt text](/images/sp_details.png)

**Conditional Access Policies**  
![alt text](/images/caps.png)

**Conditional Access Policies Details**  
![alt text](/images/caps_details.png)

**Enumeration Summary**  
![alt text](/images/enumeration_overview.png)


## 📑 HTML Report

### **General**
- Click the ⚙️ **Columns** button to show or hide specific columns.
- Click 💾 **Export CSV** to download the currently visible data as a CSV file.
- Click 👁 **Share View** to copy filters, sorting, and column selection as a shareable link.
- Click 🧰 **Preset Views** to apply preconfigured filters and column selections.
- Click 🔄 **Reset View** to reset the view to the default.
- Click on object names to jump to detailed information, even in other reports.
- When using internal navigation, press the browser’s back button to return.
- Browser search can locate content even within collapsed *Details* sections.
- Some table header fields display helper text on mouse hover.
- Sort data by clicking a table header.

### **Filtering**
- If no operator is specified, filtering defaults to *contains*.
- Use `=` for an exact match.
- Use `^` for *starts with* (e.g., `^Mallory`).
- Use `$` for *ends with* (e.g., `$domain.ch`).
- Comparison operators like `>`, `<`, `>=`, `<=` are supported (numeric values only).
- Filters can be negated by starting with `!` (except for numeric comparisons). Examples: `!Mallory`, `!=Mallory`,`!^Mallory` or `!$domain.ch`.
- Use `=empty` to match empty cells, or `!=empty` to match non-empty cells.
- Use `||` to match any of multiple values in the same column (e.g., `Admin || Guest`).
- To apply OR logic across columns, use `or_`, `group1_`, `group2_`... directly in a filter field. Examples: in column 1: `or_>1`, in column 2: `or_!Mallory`
- *Note:* The **DisplayName** column also includes the object's ID (invisible), so filtering by ID is also possible.

### **Controls using GET Parameters**
- *Filtering*: Apply filters using field names as HTTP GET parameters, e.g., `?EntraRoles=>1&Enabled=true`.  
To apply OR logic across columns, use `or_` or `group1_` prefix in (e.g., `?or_EntraRoles=>0&or_GrpMem=>0`).
- *Column Selection*:  Choose which columns to display using the `columns` parameter. Example: `?columns=DisplayName,Owner`.
- *Sorting*: Sort the data using `sort` and `sortDir` parameters. Example: `?sort=Impact&sortDir=desc` or `?sort=OwnerCount&sortDir=asc`.
- *Object Details*: Jump directly to a specific object in the report using an anchor (`#`) and the object id, e.g. `#%ObjectID%`.

### **Rating**
- **Impact**: Represents the amount or severity of permission the object has.
- **Likelihood**: Represents how easily the object can be influenced or how well it is protected.
- **Risk**: Calculated score: *Impact × Likelihood = Risk*.
- **Important**: 
    - This scoring is meant as a basic evaluation to help sort and prioritize entries in the table.
    - Risk scores are not directly comparable across different object types or reports.
    - It is not intended to replace a full risk assessment.

## 🔧Under the Hood

### Role Categorization
Entra ID and Azure roles are roughly categorized into different tier levels. This categorization influences the impact scores of objects assigned to those roles.
The goal is to assign a higher impact score to users with more powerful roles (e.g., Global Administrator) compared to users with less critical roles (e.g., Global Reader), even if both are considered privileged roles by Microsoft.

>Note:
For Azure roles, this categorization is less precise, as the actual impact depends heavily on the scope of the role assignment. For example, an Owner role on a single virtual machine has significantly less impact than when the same role is applied to an entire subscription. It might also be a test subscription with no resources at all.
<details>
<summary>Entra ID Roles</summary>

| Role Name                                      | Tier-Level | GUID                                   |
|------------------------------------------------|------------|----------------------------------------|
| Global Administrator                          | 0          | 62e90394-69f5-4237-9190-012177145e10   |
| Partner Tier2 Support                         | 0          | e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8   |
| Privileged Authentication Administrator       | 0          | 7be44c8a-adaf-4e2a-84d6-ab2649e08a13   |
| Privileged Role Administrator                 | 0          | e8611ab8-c189-46e8-94e1-60213ab1f814   |
| Domain Name Administrator                     | 0          | 8329153b-31d0-4727-b945-745eb3bc5f31   |
| External Identity Provider Administrator      | 0          | be2f45a1-457d-42af-a067-6ec1fa63bc45   |
| Hybrid Identity Administrator                 | 0          | 8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2   |
| Application Administrator                     | 0          | 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3   |
| Cloud Application Administrator               | 0          | 158c047a-c907-4556-b7ef-446551a6b5f7   |
| Security Administrator                        | 1          | 194ae4cb-b126-40b2-bd5b-6091b380977d   |
| Conditional Access Administrator              | 1          | b1be1c3e-b65d-4f19-8427-f6fa0d97feb9   |
| Authentication Administrator                  | 1          | c4e39bd9-1100-46d3-8c65-fb160da0071f   |
| Azure DevOps Administrator                    | 1          | e3973bdf-4987-49ae-837a-ba8e231c7286   |
| Directory Writers                             | 1          | 9360feb5-f418-4baa-8175-e2a00bac4301   |
| Exchange Administrator                        | 1          | 29232cdf-9323-42fd-ade2-1d097af3e4de   |
| Groups Administrator                          | 1          | fdd7a751-b60b-444a-984c-02652fe8fa1c   |
| Helpdesk Administrator                        | 1          | 729827e3-9c14-49f7-bb1b-9608f156bbb8   |
| Identity Governance Administrator             | 1          | 45d8d3c5-c802-45c6-b32a-1d70b5e1e86e   |
| Intune Administrator                          | 1          | 3a2c62db-5318-420d-8d74-23affee5d9d5   |
| Knowledge Administrator                       | 1          | b5a8dcf3-09d5-43a9-a639-8e29ef291470   |
| Knowledge Manager                             | 1          | 744ec460-397e-42ad-a462-8b3f9747a02c   |
| Lifecycle Workflows Administrator             | 1          | 59d46f88-662b-457b-bceb-5c3809e5908f   |
| Directory Synchronization Accounts            | 1          | d29b2b05-8046-44ba-8758-1e26182fcf32   |
| On Premises Directory Sync Account            | 1          | a92aed5d-d78a-4d16-b381-09adb37eb3b0   |
| Partner Tier1 Support                         | 1          | 4ba39ca4-527c-499a-b93d-d9b492c50246   |
| Password Administrator                        | 1          | 966707d0-3269-4727-9be2-8c3a10f19b9d   |
| SharePoint Administrator                      | 1          | f28a1f50-f6e7-4571-818b-6a12f2af6b6c   |
| Teams Administrator                           | 1          | 69091246-20e8-4a56-aa4d-066075b2a7a8   |
| User Administrator                            | 1          | fe930be7-5e62-47db-91af-98c3a49a38b1   |
| Windows 365 Administrator                     | 1          | 11451d60-acb2-45eb-a7d6-43d0f0125c13   |
| Yammer Administrator                          | 1          | 810a2642-a034-447f-a5e8-41beaa378541   |
| Authentication Policy Administrator           | 2          | 0526716b-113d-4c15-b2c8-68e3c22b9f80   |
| Azure AD Joined Device Local Administrator    | 2          | 9f06204d-73c1-4d4c-880a-6edb90606fd8   |
| Cloud Device Administrator                    | 2          | 7698a772-787b-4ac8-901f-60d6b08affd2   |
| Global Reader                                 | 2          | f2ef992c-3afb-46b9-b7cf-a126ee74c451   |
| Guest Inviter                                 | 2          | 95e79109-95c0-4d8e-aee3-d01accf2d47b   |

</details>

<details>
<summary>Azure Roles</summary>

| Role Name                                                          | Tier-Level | GUID                                   |
|--------------------------------------------------------------------|------------|----------------------------------------|
| Owner                                                              | 0          | 8e3af657-a8ff-443c-a75c-2fe8c4bcb635   |
| User Access Administrator                                          | 0          | 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9   |
| Contributor                                                        | 0          | b24988ac-6180-42a0-ab88-20f7382dd24c   |
| Role Based Access Control Administrator                            | 0          | f58310d9-a9f6-439a-9e8d-f62e7b41a168   |
| Reservations Administrator                                         | 0          | a8889054-8d42-49c9-bc1c-52486c10e7cd   |
| Security Admin                                                     | 1          | fb1c8493-542b-48eb-b624-b4c8fea62acd   |
| Virtual Machine Contributor                                        | 1          | 9980e02c-c2be-4d73-94e8-173b1dc7cf3c   |
| Virtual Machine Data Access Administrator                          | 1          | 66f75aeb-eabe-4b70-9f1e-c350c4c9ad04   |
| Virtual Machine Administrator Login                                | 1          | 1c0163c0-47e6-4577-8991-ea5c82e286e4   |
| Windows Admin Center Administrator Login                           | 1          | a6333a3e-0164-44c3-b281-7a577aff287f   |
| Container Registry Contributor and Data Access Configuration Administrator | 1 | 3bc748fc-213d-45c1-8d91-9da5725539b9   |
| Key Vault Administrator                                            | 1          | 00482a5a-887f-4fb3-b363-3b7fe8e74483   |
| Key Vault Data Access Administrator                                | 1          | 8b54135c-b56d-4d72-a534-26097cfdc8d8   |
| Key Vault Secrets Officer                                          | 1          | b86a8fe4-44ce-4948-aee5-eccb2c155cd7   |
| Key Vault Secrets User                                             | 1          | 4633458b-17de-408a-b874-0445c86b69e6   |
| Azure Kubernetes Service RBAC Admin                                | 1          | 3498e952-d568-435e-9b2c-8d77e338d7f7   |
| Azure Kubernetes Service RBAC Cluster Admin                        | 1          | b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b   |
| Azure Arc Kubernetes Admin                                         | 1          | dffb1e0c-446f-4dde-a09f-99eb5cc68b96   |
| Azure Arc Kubernetes Cluster Admin                                 | 1          | 8393591c-06b9-48a2-a542-1bd6b377f6a2   |
| Azure Arc VMware VM Contributor                                    | 1          | b748a06d-6150-4f8a-aaa9-ce3940cd96cb   |
| Storage Account Contributor                                        | 1          | 17d1049b-9a84-46fb-8f53-869881c3d3ab   |
| Reader                                                             | 2          | acdd72a7-3385-48ef-bd42-f606fba81ae7   |
| SecurityReader                                                     | 2          | 39bc4728-0917-49c7-9d2c-d95423bc2eb4   |
| Virtual Machine User Login                                         | 3          | fb879df8-f326-4884-b1cf-06f3ad86be52   |
| Desktop Virtualization User                                        | 3          | 1d18fff3-a72a-46b5-b4a9-0b38a3cd7e63   |

</details>

### API Permission Categorization
Certain API permissions allow an application to directly escalate to Global Administrator privileges. Therefore, several API permissions are categorized into different severity levels. This categorization influences the impact score of applications that have these permissions assigned — either as application permissions or delegated permissions for users.
<details>
<summary>Application Permission</summary>

| Permission                                                  | Severity   | GUID                                   |
|-------------------------------------------------------------|------------|----------------------------------------|
| RoleManagement.ReadWrite.Directory                          | Dangerous  | 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8   |
| AppRoleAssignment.ReadWrite.All                             | Dangerous  | 06b708a9-e830-4db3-a914-8e69da51d44f   |
| Application.ReadWrite.All                                   | Dangerous  | 1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9   |
| RoleAssignmentSchedule.ReadWrite.Directory                  | Dangerous  | dd199f4a-f148-40a4-a2ec-f0069cc799ec   |
| PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup         | Dangerous  | 41202f2c-f7ab-45be-b001-85c9728b9d69   |
| PrivilegedAccess.ReadWrite.AzureADGroup                     | Dangerous  | 2f6817f8-7b12-4f0f-bc18-eeaf60705a9e   |
| RoleEligibilitySchedule.ReadWrite.Directory                 | Dangerous  | fee28b28-e1f3-4841-818e-2704dc62245f   |
| PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup        | Dangerous  | 618b6020-bca8-4de6-99f6-ef445fa4d857   |
| Domain.ReadWrite.All                                        | Dangerous  | 7e05723c-0bb0-42da-be95-ae9f08a6e53c   |
| ADSynchronization.ReadWrite.All                             | High       | ab43b826-2c7a-4aff-9ecd-d0629d0ca6a9   |
| EntitlementManagement.ReadWrite.All                         | High       | 9acd699f-1e81-4958-b001-93b1d2506e19   |
| Organization.ReadWrite.All                                  | High       | 292d869f-3427-49a8-9dab-8c70152b74e9   |
| Policy.ReadWrite.PermissionGrant                            | High       | a402ca1c-2696-4531-972d-6e5ee4aa11ea   |
| RoleManagementPolicy.ReadWrite.AzureADGroup                 | High       | b38dcc4d-a239-4ed6-aa84-6c65b284f97c   |
| RoleManagementPolicy.ReadWrite.Directory                    | High       | 31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad   |
| Policy.ReadWrite.AuthenticationMethod                       | High       | 29c18626-4985-4dcd-85c0-193eef327366   |
| User.DeleteRestore.All                                      | High       | eccc023d-eccf-4e7b-9683-8813ab36cecc   |
| User.EnableDisableAccount.All                               | High       | 3011c876-62b7-4ada-afa2-506cbbecc68c   |
| DelegatedPermissionGrant.ReadWrite.All                      | High       | 8e8e4742-1d95-4f68-9d56-6ee75648c72a   |
| Policy.ReadWrite.ConditionalAccess                          | High       | 01c0a623-fc9b-48e9-b794-0756f8e8f067   |
| DeviceManagementConfiguration.ReadWrite.All                 | High       | 9241abd9-d0e6-425a-bd4f-47ba86e767a4   |
| DeviceManagementRBAC.ReadWrite.Al                           | High       | e330c4f0-4170-414e-a55a-2f022ec2b57b   |
| Directory.ReadWrite.All                                     | High       | 19dbc75e-c2e2-444c-a770-ec69d8559fc7   |
| Group.ReadWrite.All                                         | High       | 62a82d76-70ea-41e2-9197-370581804d09   |
| GroupMember.ReadWrite.All                                   | High       | dbaae8cf-10b5-4b86-a4a1-f871c94c6695   |
| UserAuthenticationMethod.ReadWrite.All                      | High       | 50483e42-d915-4231-9639-7fdb7fd190e5   |
| User-PasswordProfile.ReadWrite.All                          | High       | 56760768-b641-451f-8906-e1b8ab31bca7   |
| Sites.FullControl.All                                       | High       | a82116e5-55eb-4c41-a434-62fe8a61c773   |
| Sites.FullControl.All SharePointAPI                         | High       | 678536fe-1083-478a-9c59-b99265e6b0d3   |
| Sites.Manage.All SharePointAPI                              | High       | 9bff6588-13f2-4c48-bbf2-ddab62256b36   |
| Sites.Read.All SharePointAPI                                | High       | d13f72ca-a275-4b96-b789-48ebcc4da984   |
| Sites.ReadWrite.All SharePointAPI                           | High       | fbcd29d2-fcca-4405-aded-518d457caae4   |
| Sites.Manage.All                                            | High       | 0c0bf378-bf22-4481-8f81-9e89a9b4960a   |
| Sites.Read.All                                              | High       | 332a536c-c7ef-4017-ab91-336970924f0d   |
| Sites.ReadWrite.All                                         | High       | 9492366f-7969-46a4-8d15-ed1a20078fff   |
| Files.Read.All                                              | High       | 01d4889c-1287-42c6-ac1f-5d1e02578ef6   |
| Files.ReadWrite.All                                         | High       | 75359482-378d-4052-8f01-80520e7db3cd   |
| DeviceLocalCredential.Read.All                              | High       | db51be59-e728-414b-b800-e0f010df1a79   |
| AdministrativeUnit.ReadWrite.All                            | High       | 5eb59dd3-1da2-4329-8733-9dabdc435916   |
| User.ReadWrite.All                                          | Medium     | 741f803b-c850-494e-b5df-cde7c675a1ca   |
| Chat.Read.All                                               | Medium     | 6b7d71aa-70aa-4810-a8d9-5d9fb2830017   |
| Chat.ReadWrite.All                                          | Medium     | 294ce7c9-31ba-490a-ad7d-97a7d075e4ed   |
| Calendars.ReadWrite                                         | Medium     | ef54d2bf-783f-4e0f-bca1-3210c0444d99   |
| Mail.Read                                                   | Medium     | 810c84a8-4a9e-49e6-bf7d-12d183f40d01   |
| Mail.ReadWrite                                              | Medium     | e2a3a72e-5f79-4c64-b1b1-878b674786c9   |
| Mail.Send                                                   | Medium     | b633e1c5-b582-4048-a93e-9f11b44c7e96   |
| OnlineMeetings.ReadWrite.All                                | Medium     | b8bb2037-6e08-44ac-a4ea-4674e010e2a4   |
| CustomSecAttributeAssignment.ReadWrite.All                  | Medium     | de89b5e4-5b8f-48eb-8925-29c2b33bd8bd   |
| ServicePrincipalEndpoint.ReadWrite.All                      | Medium     | 89c8469c-83ad-45f7-8ff2-6e3d4285709e   |

</details>

<details>
<summary>Delegated Permission</summary>

| Permission                                           | Severity | GUID                                   |
|------------------------------------------------------|----------|----------------------------------------|
| RoleManagement.ReadWrite.Directory                   | Dangerous| d01b97e9-cbc0-49fe-810a-750afd5527a3   |
| AppRoleAssignment.ReadWrite.All                      | Dangerous| 84bccea3-f856-4a8a-967b-dbe0a3d53a64   |
| Application.ReadWrite.All                            | Dangerous| bdfbf15f-ee85-4955-8675-146e8e5296b5   |
| RoleAssignmentSchedule.ReadWrite.Directory           | Dangerous| 8c026be3-8e26-4774-9372-8d5d6f21daff   |
| PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup  | Dangerous| 06dbc45d-6708-4ef0-a797-f797ee68bf4b   |
| PrivilegedAccess.ReadWrite.AzureADGroup              | Dangerous| 32531c59-1f32-461f-b8df-6f8a3b89f73b   |
| RoleEligibilitySchedule.ReadWrite.Directory          | Dangerous| 62ade113-f8e0-4bf9-a6ba-5acb31db32fd   |
| PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup | Dangerous| ba974594-d163-484e-ba39-c330d5897667   |
| Domain.ReadWrite.All                                 | Dangerous| 0b5d694c-a244-4bde-86e6-eb5cd07730fe   |
| EntitlementManagement.ReadWrite.All                  | High     | ae7a573d-81d7-432b-ad44-4ed5c9d89038   |
| Organization.ReadWrite.All                           | High     | 46ca0847-7e6b-426e-9775-ea810a948356   |
| Policy.ReadWrite.PermissionGrant                     | High     | 2672f8bb-fd5e-42e0-85e1-ec764dd2614e   |
| RoleManagementPolicy.ReadWrite.AzureADGroup          | High     | 0da165c7-3f15-4236-b733-c0b0f6abe41d   |
| RoleManagementPolicy.ReadWrite.Directory             | High     | 1ff1be21-34eb-448c-9ac9-ce1f506b2a68   |
| Policy.ReadWrite.AuthenticationMethod                | High     | 7e823077-d88e-468f-a337-e18f1f0e6c7c   |
| User.DeleteRestore.All                               | High     | 4bb440cd-2cf2-4f90-8004-aa2acd2537c5   |
| User.EnableDisableAccount.All                        | High     | f92e74e7-2563-467f-9dd0-902688cb5863   |
| DelegatedPermissionGrant.ReadWrite.All               | High     | 41ce6ca6-6826-4807-84f1-1c82854f7ee5   |
| Policy.ReadWrite.ConditionalAccess                   | High     | ad902697-1014-4ef5-81ef-2b4301988e8c   |
| DeviceManagementConfiguration.ReadWrite.All          | High     | 0883f392-0a7a-443d-8c76-16a6d39c7b63   |
| DeviceManagementRBAC.ReadWrite.All                   | High     | 0c5e8a55-87a6-4556-93ab-adc52c4d862d   |
| Directory.ReadWrite.All                              | High     | c5366453-9fb0-48a5-a156-24f0c49a4b84   |
| Group.ReadWrite.All                                  | High     | 4e46008b-f24c-477d-8fff-7bb4ec7aafe0   |
| GroupMember.ReadWrite.All                            | High     | f81125ac-d3b7-4573-a3b2-7099cc39df9e   |
| UserAuthenticationMethod.ReadWrite.All               | High     | b7887744-6746-4312-813d-72daeaee7e2d   |
| Sites.FullControl.All                                | High     | 5a54b8b3-347c-476d-8f8e-42d5c7424d29   |
| Sites.Manage.All                                     | High     | 65e50fdc-43b7-4915-933e-e8138f11f40a   |
| User-PasswordProfile.ReadWrite.All                   | High     | 56760768-b641-451f-8906-e1b8ab31bca7   |
| Sites.Read.All                                       | High     | 205e70e5-aba6-4c52-a976-6d2d46c48043   |
| Sites.ReadWrite.All                                  | High     | 89fe6a52-be36-487e-b7d8-d061c450a026   |
| Files.Read.All                                       | High     | df85f4d6-205c-4ac5-a5ea-6bf408dba283   |
| Files.ReadWrite.All                                  | High     | 863451e7-0667-486c-a5d6-d135439485f0   |
| DeviceLocalCredential.Read.All                       | High     | 9917900e-410b-4d15-846e-42a357488545   |
| AdministrativeUnit.ReadWrite.All                     | High     | 7b8a2d34-6b3f-4542-a343-54651608ad81   |
| User.ReadWrite.All                                   | Medium   | 204e0828-b5ca-4ad8-b9f3-f32a958e7cc4   |
| Chat.ReadWrite.All                                   | Medium   | 7e9a077b-3711-42b9-b7cb-5fa5f3f7fea7   |
| Mail.Read                                            | Medium   | 570282fd-fa5c-430d-a7fd-fc8dc98a9dca   |
| Mail.ReadWrite                                       | Medium   | 024d486e-b451-40bb-833d-3e66d98c5c73   |
| Mail.Send                                            | Medium   | e383f46e-2787-4529-855e-0e479a3ffac0   |
| CustomSecAttributeAssignment.ReadWrite.All           | Medium   | ca46335e-8453-47cd-a001-8459884efeae   |
| ServicePrincipalEndpoint.ReadWrite.All               | Medium   | 7297d82c-9546-4aed-91df-3d4f0a9b3ff0   |
| BitlockerKey.Read.All                                | Medium   | b27a61ec-b99c-4d6a-b126-c4375d08ae30   |
| Calendars.Read                                       | Medium   | 465a38f9-76ea-45b9-9f34-9e8b0d4b0b42   |
| Calendars.Read.Shared                                | Medium   | 2b9c4092-424d-4249-948d-b43879977640   |
| Calendars.ReadWrite                                  | Medium   | 1ec239c2-d7c9-4623-a91a-a9775856bb36   |
| Calendars.ReadWrite.Shared                           | Medium   | 12466101-c9b8-439a-8589-dd09ee67e8e9   |
| ChannelMessage.ReadWrite                             | Medium   | 5922d31f-46c8-4404-9eaf-2117e390a8a4   |
| ChannelMessage.Send                                  | Medium   | ebf0f66e-9fb1-49e4-a278-222f76911cf4   |
| Chat.ReadWrite                                       | Medium   | 9ff7295e-131b-4d94-90e1-69fde507ac11   |
| Directory.AccessAsUser.All                           | Medium   | 0e263e50-5827-48a4-b97c-d940288653c7   |
| Directory.Read.All                                   | Medium   | 06da0dbc-49e2-44d2-8312-53f166ab848a   |
| Files.ReadWrite                                      | Medium   | 5c28f0bf-8a70-41f1-8ab2-9032436ddb65   |
| MailboxItem.ImportExport                             | Medium   | df96e8a0-f4e1-4ecf-8d83-a429f822cbd6   |
| offline_access                                       | Medium   | 7427e0e9-2fba-42fe-b0c0-848c9e6a8182   |
| openid                                               | Low      | 37f7f235-527c-4136-accd-4a02d197296e   |
| email                                                | Low      | 64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0   |
| profile                                              | Low      | 14dad69e-099b-42c9-810b-d002981feec1   |
| User.Read                                            | Low      | 14dad69e-099b-42c9-810b-d002981feec1   |

</details>

### Microsft First Party Enterprise Applications
By default, Microsoft applications are filtered out to simplify the review of Enterprise Applications. Use the `-IncludeMsApps` switch to include them. Applications from the following tenants are treated as Microsoft-owned:
- f8cdef31-a31e-4b4a-93e4-5f571e91255a
- 72f988bf-86f1-41af-91ab-2d7cd011db47
- 33e01921-4d64-4f8c-a055-5bdaffd5e33d
- cdc5aeea-15c5-4db6-b079-fcadd2505dc2


### Checks Performed
The following table roughly summarizes the checks performed, along with their impact on scoring and whether a warning is displayed.

<details>
<summary>Checks Performed</summary>

|Area|Check|Impacts Score|Warning Displayed|
|-|-|-|-|
|Groups|Is a public M365 group|Yes|Yes|
|Groups|Is Dynamic / Is Dynamic and potentially dangerous query|Yes|Yes|
|Groups|Entra Roles (Active and Eligible)|Yes|Yes|
|Groups|Azure Roles (Active and Eligible)|Yes|Yes|
|Groups|Used for AppRole|Yes|Yes|
|Groups|Internal/Foreign SP as Owner|Yes|Yes|
|Groups|In restricted AU|Yes|Yes|
|Groups|Nested in privileged Group|Yes|Yes|
|Groups|Used in CAP|Yes|Yes|
|Groups|Group Type|Yes|No|
|Groups|Security Enabled|Yes|No|
|Groups|Nested Member Active|Yes|No|
|Groups|Owners|Yes|No|
|Groups|Nested Owners|Yes|No|
|Groups|Guest as Owner|Yes|Yes|
|Groups|On-Prem Sync|Yes|No|
|Groups|Members (transitive)|Yes|No|
|Groups|Role-Assignable|Yes|No|
|Groups|PIM for Groups: Onboarded|No|No|
|Groups|PIM for Groups: Eligible member of privileged Group|Yes|Yes|
|Groups|PIM for Groups: Eligible owner of privileged Group|Yes|Yes|
|Groups|PIM for Groups: Unprotected group nested in protected group|No|Yes|
|EnterpriseApp|Entra Role|Yes|Yes|
|EnterpriseApp|Azure Role|Yes|Yes|
|EnterpriseApp|Foreign|Yes|Yes|
|EnterpriseApp|API Permission (Application)|Yes|Yes|
|EnterpriseApp|API Permission (Delegated)|Yes|Yes|
|EnterpriseApp|Credentials|Yes|Yes|
|EnterpriseApp|Owners|Yes|Yes|
|EnterpriseApp|Ownership over App Registrations|Yes|Yes|
|EnterpriseApp|Ownership of other Service Principals|Yes|Yes|
|EnterpriseApp|AppLock|(Yes)|No|
|EnterpriseApp|App owns AppRegistration|Yes|Yes|
|EnterpriseApp|Member / owner of groups|Yes|(Yes)|
|EnterpriseApp|AppRoles|Yes|No|
|EnterpriseApp|AppRole requirements|Yes|No|
|EnterpriseApp|Inactive|No|No|
|EnterpriseApp|Last successful sign-in (days)|No|No|
|AppRegistrations|Credentials|Yes|Yes|
|AppRegistrations|AppRoles|Yes|No|
|AppRegistrations|AppRedirectURL|No|No|
|AppRegistrations|AppLock|Yes|No|
|AppRegistrations|Owners|Yes|Yes|
|AppRegistrations|(Cloud) App Admins scoped|No|No|
|AppRegistrations|Privileges of the corresponding SP|Yes|No|
|AppRegistrations|Sign-in audience|No|No|
|ManagedIdentity|Owners|Yes|Yes|
|ManagedIdentity|Entra Role|Yes|Yes|
|ManagedIdentity|Azure Role|Yes|Yes|
|ManagedIdentity|API (App)|Yes|Yes|
|ManagedIdentity|Ownership over App Registrations|Yes|Yes|
|ManagedIdentity|Ownership of other Service Principals|Yes|Yes|
|ManagedIdentity|Member / owner of groups|Yes|(Yes)|
|User|Entra Roles (Active and Eligible)|Yes|Yes|
|User|Azure Roles (Active and Eligible)|Yes|Yes|
|User|Privileged group membership (Active and Eligible)|Yes|Yes|
|User|Privileged group ownership (Active and Eligible)|Yes|Yes|
|User|Entra Connect Sync user|Yes|Yes|
|User|Entra Connect Cloud Sync user|Yes|Yes|
|User|AppRegistration ownership|Yes|Yes|
|User|EnterpriseApplication ownership|Yes|Yes|
|User|No MFA-factor registered|Yes|Yes|
|User|Is protected|Yes|No|
|User|Inactive|No|No|
|User|Member / owner of groups|Yes|(Yes)|
|User|Synced from on-prem|Yes|No|
|CAP|No or misconfigured policy for legacy authentication|-|Yes|
|CAP|No or misconfigured policy for blocking device code flow|-|Yes|
|CAP|No or misconfigured policy for limiting the registrations of security information|-|Yes|
|CAP|No or misconfigured policy for targeting risky sign-ins|-|Yes|
|CAP|No or misconfigured policy for targeting user risk|-|Yes|
|CAP|No or misconfigured policy enforcing MFA|-|Yes|
|CAP|No policy enforcing Authentication Strength|-|Yes|
|CAP|Inclusion of roles which have scoped assignments|-|Yes|
</details>

## 🛡️ Detection
EntraFalcon is not stealthy and can be detected in environments where Microsoft Graph API and Azure sign-in activity are logged and monitored.

When a full enumeration is performed, the tool actively initiates two interactive logins and two non-interactive logins (refresh to another API and another FOCI client):
|Application ID|Type|Resource ID|Purpose|
|-|-|-|-|
|1b730954-1685-4b74-9bfd-dac224a7b894|Interactive|00000003-0000-0000-c000-000000000000|Retrieve PIM for Groups data|
|04b07795-8ddb-461a-bbee-02f9e1bf7b46|Interactive|00000003-0000-0000-c000-000000000000|	Retrieve general tenant object data|
|eb20f3e3-3dce-4d2c-b721-ebb8d4414067|Non-Interactive|00000003-0000-0000-c000-000000000000|Retrieve PIM for Entra / Azure roles|
|04b07795-8ddb-461a-bbee-02f9e1bf7b46|Non-Interactive|797f4846-ba00-4fd7-ba43-dac1f8f63013|Retrieve Azure IAM role assignment data|

For data collection, the tool sends multiple requests to the Microsoft Graph API and, optionally, the Azure ARM API—one or more per object. Where possible, it leverages the Graph Batch endpoint to reduce the number of individual requests and improve efficiency.

Interactive sign-ins use the browser's User-Agent. All non-interactive sign-ins and API requests (Graph and ARM) use EntraFalcon as the User-Agent, unless changed with the -UserAgent parameter.

To detect usage of EntraFalcon, blue teams can monitor for the listed application IDs in sign-in logs, look for unusual volumes of Graph API traffic, or analyze token refresh and batch request behavior.

## 🕳️ Known Limitations
- **M365 RBAC**: Not assessed
- **Defender for Endpoint RBAC**: Not assessed
- **Intune RBAC**: Not assessed
- **Cloud Environment**: Cloud platforms evolve rapidly. As a result, some assessments or detections may become outdated or inaccurate over time. Moreover, tenants are becoming increasingly complex, and specific configurations or combinations of settings may lead to inaccurate results. While we strive to keep EntraFalcon up to date, it is always recommended to validate findings independently and not rely solely on the tool for critical decisions.


## 📦 Integrated External Tools
The following submodules have been forked and integrated into EntraFalcon to support authentication, Microsoft Graph interaction and report charts:
- [EntraTokenAid](https://github.com/zh54321/EntraTokenAid)
- [GraphRequest](https://github.com/zh54321/GraphRequest)
- [GraphBatchRequest](https://github.com/zh54321/GraphBatchRequest)
- [Chart.js](https://github.com/chartjs/Chart.js)
