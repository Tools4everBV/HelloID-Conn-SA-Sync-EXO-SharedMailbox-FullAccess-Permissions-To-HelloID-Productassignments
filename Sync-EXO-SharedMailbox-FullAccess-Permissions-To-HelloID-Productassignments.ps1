#####################################################
# HelloID-Conn-SA-Sync-EXO-SharedMailbox-FullAccess-Permissions-To-HelloID-Productassignments
#
# Version: 1.0.0
#####################################################
# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

switch ($verboseLogging) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
# $script:PortalBaseUrl = "" # Set from Global Variable
# $portalApiKey = "" # Set from Global Variable
# $portalApiSecret = "" # Set from Global Variable

# Exchange Online Connection Configuration
# $AzureADOrganization = "" # Set from Global Variable
# $AzureADtenantID = "" # Set from Global Variable
# $AzureADAppId = "" # Set from Global Variable
# $AzureADAppSecret = "" # Set from Global Variable
$exchangeMailboxesFilter = "DisplayName -like 'shared-*'" # Optional, when no filter is provided ($exchangeMailboxesFilter = $null), all mailboxes will be queried

# PowerShell commands to import
$exchangeOnlineCommands = @(
    "Get-User"
    , "Get-EXOMailbox"
    , "Get-EXOMailboxPermission"
) # Fixed list of commands required by script - only change when missing commands

#HelloID Self service Product Configuration
$ProductSkuPrefix = 'SHRDMBX' # Optional, when no SkuPrefix is provided ($ProductSkuPrefix = $null), all products will be queried
$PowerShellActionName = "Grant-FullAccessPermissionToMailbox" # Define the name of the PowerShell action

#Correlation Configuration
# The name of the property of HelloID users to match to EXO users - value has to match the value of the propertye specified in $exoUserCorrelationProperty
$helloIDUserCorrelationProperty = "username"
# The name of the property of EXO users to match to HelloID users - value has to match the value of the propertye specified in $helloIDUserCorrelationProperty
$exoUserCorrelationProperty = "userPrincipalName"

#region functions

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ""
        }

        if ($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException") {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or $($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException")) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [Parameter(Mandatory = $false)]
        $PageSize,

        [string]
        $ContentType = "application/json"
    )

    try {
        Write-Verbose "Switching to TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose "Setting authorization headers"
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)
        $headers.Add("Accept", $ContentType)

        $splatWebRequest = @{
            Uri             = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers         = $headers
            Method          = $Method
            UseBasicParsing = $true
            ErrorAction     = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatWebRequest["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatWebRequest -Verbose:$false
                if (($response.PsObject.Properties.Match("pageData") | Measure-Object).Count -gt 0) {
                    $dataset = $response.pageData
                }
                else {
                    $dataset = $response
                }

                if ($dataset -is [array]) {
                    [void]$data.AddRange($dataset)
                }
                else {
                    [void]$data.Add($dataset)
                }
            
                $skip += $take
            }until(($dataset | Measure-Object).Count -ne $take)

            return $data
        }
        else {
            if ($Body) {
                Write-Verbose "Adding body to request"
                $splatWebRequest["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatWebRequest -Verbose:$false

            return $response
        }

    }
    catch {
        throw $_
    }
}
#endregion functions

#region script
Hid-Write-Status -Event Information -Message "Starting synchronization of Exchange Online Users with FullAccess to SharedMailboxes to HelloID ResourceOwner Groupmemberships"
Hid-Write-Status -Event Information -Message "------[HelloID]------"
#region Get HelloID Products
try {
    Write-Verbose "Querying Self service products from HelloID"

    $splatParams = @{
        Method = "GET"
        Uri    = "selfservice/products"
    }
    $helloIDSelfServiceProducts = Invoke-HIDRestMethod @splatParams

    # Filter for products with specified Sku Prefix
    if (-not[String]::IsNullOrEmpty($ProductSkuPrefix)) {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts | Where-Object { $_.code -like "$ProductSkuPrefix*" }
    }
    else {
        $helloIDSelfServiceProductsInScope = $null
        $helloIDSelfServiceProductsInScope = $helloIDSelfServiceProducts
    }

    Hid-Write-Status -Event Success -Message "Successfully queried Self service products from HelloID (after filtering for products with specified sku prefix only). Result count: $(($helloIDSelfServiceProductsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service products from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Products

#region Get HelloID Users
try {
    Write-Verbose "Querying Users from HelloID"

    $splatWebRequest = @{
        Method   = "GET"
        Uri      = "users"
        PageSize = 1000
    }
    $helloIDUsers = Invoke-HIDRestMethod @splatWebRequest

    # $helloIDUsersGroupedOnUserName = $helloIDUsers | Group-Object -Property "userName" -AsHashTable -AsString
    # $helloIDUsersGroupedOnUserGUID = $helloIDUsers | Group-Object -Property "userGUID" -AsHashTable -AsString
    $helloIDUsersGrouped = $helloIDUsers | Group-Object -Property $helloIDUserCorrelationProperty -AsHashTable -AsString

    Hid-Write-Status -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsers | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Users from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Users

#region Get actions of Product
try {
    [System.Collections.ArrayList]$helloIDSelfServiceProductsInScopeWithActions = @()
    Write-Verbose "Querying HelloID Self service Products with Actions"
    foreach ($helloIDSelfServiceProductInScope in $helloIDSelfServiceProductsInScope) {
        #region Get objects with Full Access to Shared Mailbox
        try {
            $helloIDSelfServiceProductInScopeWithActionsObject = [PSCustomObject]@{
                productId   = $helloIDSelfServiceProductInScope.selfServiceProductGUID
                name        = $helloIDSelfServiceProductInScope.name
                description = $helloIDSelfServiceProductInScope.description
                code        = $helloIDSelfServiceProductInScope.code
                actions     = [System.Collections.ArrayList]@()
            }

            Write-Verbose "Querying actions of Product [$($helloIDSelfServiceProductInScope.selfServiceProductGUID)]"

            $splatParams = @{
                Method = "GET"
                Uri    = "products/$($helloIDSelfServiceProductInScope.selfServiceProductGUID)"
            }
            $helloIDSelfServiceProduct = Invoke-HIDRestMethod @splatParams

            # Add actions of all "grant" states
            $helloIDSelfServiceProductActions = $helloIDSelfServiceProduct.onRequest + $helloIDSelfServiceProduct.onApprove
            foreach ($helloIDSelfServiceProductAction in $helloIDSelfServiceProductActions) {
                $helloIDSelfServiceProductActionObject = [PSCustomObject]@{
                    actionGUID = $helloIDSelfServiceProductAction.actionGUID
                    name       = $helloIDSelfServiceProductAction.name
                    objectGUID = $helloIDSelfServiceProductAction.objectGUID
                }

                [void]$helloIDSelfServiceProductInScopeWithActionsObject.actions.Add($helloIDSelfServiceProductActionObject)
            }

            [void]$helloIDSelfServiceProductsInScopeWithActions.Add($helloIDSelfServiceProductInScopeWithActionsObject)

            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Success "Successfully queried actions of Product [$($helloIDSelfServiceProductInScope.selfServiceProductGUID)]. Result count: $(($helloIDSelfServiceProduct.actions | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying actions of Product [$($helloIDSelfServiceProductInScope.productId)]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
        #endregion Get objects with Full Access to Shared Mailbox
    }

    # Filter for products with specified actions
    $helloIDSelfServiceProductsInScopeWithActionsInScope = $helloIDSelfServiceProductsInScopeWithActions | Where-Object { $PowerShellActionName -in $_.actions.name }

    Hid-Write-Status -Event Success -Message "Successfully queried HelloID Self service Products with Actions (after filtering for products with specified action only). Result count: $(($helloIDSelfServiceProductsInScopeWithActionsInScope.actions | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying HelloID Self service Products with Actions. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get actions of Product

#region Get HelloID Productassignments
try {
    Write-Verbose "Querying  Self service Productassignments from HelloID"

    $splatParams = @{
        Method   = "GET"
        Uri      = "product-assignment"
        PageSize = 1000
    }
    $helloIDSelfServiceProductassignments = Invoke-HIDRestMethod @splatParams

    # Filter for for productassignments of specified products
    $helloIDSelfServiceProductassignmentsInScope = $null
    $helloIDSelfServiceProductassignmentsInScope = $helloIDSelfServiceProductassignments | Where-Object { $_.productGuid -in $helloIDSelfServiceProductsInScopeWithActionsInScope.productId }

    $helloIDSelfServiceProductassignmentsInScopeGrouped = $helloIDSelfServiceProductassignmentsInScope | Group-Object -Property productGuid -AsHashTable -AsString
    Hid-Write-Status -Event Success -Message "Successfully queried Self service Productassignments from HelloID (after filtering for productassignments of specified products only). Result count: $(($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Self service Productassignments from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Productassignments

Hid-Write-Status -Event Information -Message "------[Exchange Online]-----------"

# Import module
try {
    $moduleName = "ExchangeOnlineManagement"
    $importModule = Import-Module -Name $moduleName -ErrorAction Stop -Verbose:$false
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error importing module [$moduleName]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Connect to Exchange
try {
    # Create access token
    Write-Verbose "Creating Access Token"

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AzureADTenantId/oauth2/token"
    
    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AzureADAppID"
        client_secret = "$AzureADAppSecret"
        resource      = "https://outlook.office365.com"
    }
    
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing:$true -Verbose:$false
    $accessToken = $Response.access_token

    # Connect to Exchange Online in an unattended scripting scenario using an access token.
    Write-Verbose "Connecting to Exchange Online"

    $exchangeSessionParams = @{
        Organization     = $AzureADOrganization
        AppID            = $AzureADAppID
        AccessToken      = $accessToken
        CommandName      = $exchangeOnlineCommands
        ShowBanner       = $false
        ShowProgress     = $false
        TrackPerformance = $false
        ErrorAction      = "Stop"
    }
    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams -Verbose:$false
    
    Write-Information "Successfully connected to Exchange Online"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
    throw "Error connecting to Exchange Online. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Get Exchange Online Shared Mailboxes
try {  
    $properties = @(
        "Guid"
        , "Id"
        , "Identity"
        , "UserPrincipalName"
        , "Name"
        , "DisplayName"
        , "RecipientType"
        , "RecipientTypeDetails"
    )

    $exchangeQuerySplatParams = @{
        Filter               = $exchangeMailboxesFilter
        Properties           = $properties
        RecipientTypeDetails = "SharedMailbox"
        ResultSize           = "Unlimited"
    }

    Write-Verbose "Querying Exchange Online Shared Mailboxes that match filter [$($exchangeQuerySplatParams.Filter)]"
    $exoMailboxes = Get-EXOMailbox @exchangeQuerySplatParams | Select-Object $properties

    if (($exoMailboxes | Measure-Object).Count -eq 0) {
        throw "No Shared Mailboxes have been found"
    }

    Hid-Write-Status -Event Success -Message "Successfully queried Exchange Online Shared Mailboxes. Result count: $(($exoMailboxes | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Exchange Online Shared Mailboxes that match filter [$($exchangeQuerySplatParams.Filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

#region Get Exchange online users
# Exchange Online users are needed so all the attributes are available
try {
    Write-Verbose "Querying Exchange users"

    $exoUsers = Get-User -ResultSize Unlimited -Verbose:$false

    if (($exoUsers | Measure-Object).Count -eq 0) {
        throw "No Users have been found"
    }

    $exoUsersGroupedOnUserPrincipalName = $exoUsers | Group-Object UserPrincipalName -AsHashTable

    Hid-Write-Status -Event Success -Message "Successfully queried Exchange Online Users. Result count: $(($exoUsers | Measure-Object).Count)"
}
catch { 
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying all Exchange users. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Exchange online groups

#region Get permissions to Shared Mailbox
try {
    [System.Collections.ArrayList]$exoMailboxesWithFullAccessUsers = @()
    Write-Verbose "Querying Exchange Shared Mailboxes with Users with FullAccess"
    foreach ($exoMailbox in $exoMailboxes) {
        #region Get objects with Full Access to Shared Mailbox
        try {
            $exoMailboxWithFullAccessUsersObject = [PSCustomObject]@{
                DisplayName       = $exoMailbox.DisplayName
                Name              = $exoMailbox.Name
                UserPrincipalName = $exoMailbox.UserPrincipalName
                Id                = $exoMailbox.Id
                # Only keep letters and digits and convert to upper case, as HelloID product sku only consists of those
                Guid              = ($exoMailbox.Guid -replace "\W").ToUpper()
                Users             = [System.Collections.ArrayList]@()
            }

            Write-Verbose "Querying Full Access Permissions to Mailbox [$($exoMailbox.UserPrincipalName)]"

            $fullAccessPermissions = Get-EXOMailboxPermission -Identity $exoMailbox.UserPrincipalName -ResultSize Unlimited -Verbose:$false # Returns UPN of users, DisplayName of groups

            # Filter out "NT AUTHORITY\*" and "Domain Admins" Group
            $fullAccessPermissions = $fullAccessPermissions | Where-Object { ($_.accessRights -like "*fullaccess*") -and -not($_.Deny -eq $true) -and -not($_.User -like "NT AUTHORITY\*") -and -not($_.User -like "*\Domain Admins") }

            foreach ($fullAccessPermission in $fullAccessPermissions) {
                $fullAccessUser = $null
                # list of al the users in the mailbox. This includes the groups member from the mailbox
                if ($null -ne $fullAccessPermission.User) {
                    $fullAccessUser = $null
                    $fullAccessUser = $exoUsersGroupedOnUserPrincipalName[$($fullAccessPermission.user)]
                    if ($null -ne $fullAccessUser) {
                        $userWithFullAccessObject = [PSCustomObject]@{
                            Id                = $fullAccessUser.id
                            DisplayName       = $fullAccessUser.displayName
                            UserPrincipalName = $fullAccessUser.userPrincipalName
                        }

                        [void]$exoMailboxWithFullAccessUsersObject.Users.Add($userWithFullAccessObject)
                    }
                }
            }

            [void]$exoMailboxesWithFullAccessUsers.Add($exoMailboxWithFullAccessUsersObject)

            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Success "Successfully queried Full Access Permissions to Mailbox [$($exoMailbox.UserPrincipalName)]. Result count: $(($fullAccessPermissions | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying Full Access Permissions to Mailbox [$($exoMailbox.UserPrincipalName)] Error Message: $($errorMessage.AuditErrorMessage)"
        }
        #endregion Get objects with Full Access to Shared Mailbox
    }
    $exoMailboxesWithFullAccessUsersGrouped = $exoMailboxesWithFullAccessUsers | Group-Object -Property guid -AsHashTable -AsString

    Hid-Write-Status -Event Success -Message "Successfully queried Exchange Shared Mailboxes with Users with FullAccess. Result count: $(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Exchange Shared Mailboxes with Users with FullAccess. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get permissions to Shared Mailbox

Hid-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete product assignments
try {
    $newProductAssignmentObjects = [System.Collections.ArrayList]@()
    $obsoleteProductAssignmentObjects = [System.Collections.ArrayList]@()
    $existingProductAssignmentObjects = [System.Collections.ArrayList]@()
    foreach ($product in $helloIDSelfServiceProductsInScopeWithActionsInScope) {
        # if ($verboseLogging -eq $true) {
        #     Hid-Write-Status -Event Information -Message "Calculating new and obsolete product assignments for Product [$($product.name)]"
        # }

        # Get Group from Product Action
        $exoMailboxGuid = $product.code.replace("$ProductSkuPrefix", "")
        $exoMailbox = $null
        $exoMailbox = $exoMailboxesWithFullAccessUsersGrouped[$exoMailboxGuid]
        if (($exoMailbox | Measure-Object).Count -eq 0) {
            Hid-Write-Status -Event Error -Message "No Exchange Online Mailbox found with Guid [$($exoMailboxGuid)] for Product [$($product.name)]"
            continue
        }
        elseif (($exoMailbox | Measure-Object).Count -gt 1) {
            Hid-Write-Status -Event Error -Message "Multiple Exchange Online Mailboxes found with Guid [$($exoMailboxGuid)] for Product [$($product.name)]. Please correct this so the $adGroupCorrelationProperty of the AD group is unique"
            continue
        }

        # Get EXO user objects for additional data to match to HelloID user
        $exoUsersInScope = $exoMailbox.Users
        
        # Get HelloID user objects to assign to the product
        $productUsersInScope = [System.Collections.ArrayList]@()
        foreach ($exoUser in $exoUsersInScope) {
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersGrouped[$exoUser.$exoUserCorrelationProperty]

            if (($helloIDUser | Measure-Object).Count -eq 0) {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Error -Message "No HelloID user found with $helloIDUserCorrelationProperty [$($exoUser.$exoUserCorrelationProperty)] for EXO user [$($exoUser.Id)] for Product [$($product.name)]"
                    continue
                }
            }
            else {
                [void]$productUsersInScope.Add($helloIDUser)
            }
        }

        # Get current product assignments
        $currentProductassignments = $null
        if (($helloIDSelfServiceProductassignmentsInScope | Measure-Object).Count -ge 1) {
            $currentProductassignments = $helloIDSelfServiceProductassignmentsInScopeGrouped[$product.productId]
        }

        # Define assignments to grant
        $newProductassignments = $productUsersInScope | Where-Object { $_.userGuid -notin $currentProductassignments.userGuid }
        foreach ($newProductAssignment in $newProductassignments) {
            $newProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.productId)"
                productName            = "$($product.name)"
                userGuid               = "$($newProductAssignment.userGuid)"
                userName               = "$($newProductAssignment.userName)"
                source                 = "SyncEXOFullAccessPermissionsToProductAssignments"
                executeApprovalActions = $false
            }

            [void]$newProductAssignmentObjects.Add($newProductAssignmentObject)
        }

        # Define assignments to revoke
        $obsoleteProductassignments = $currentProductassignments | Where-Object { $_.userGuid -notin $productUsersInScope.userGuid }
        foreach ($obsoleteProductassignment in $obsoleteProductassignments) { 
            $obsoleteProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.productId)"
                productName            = "$($product.name)"
                userGuid               = "$($obsoleteProductassignment.userGuid)"
                userName               = "$($obsoleteProductassignment.userName)"
                source                 = "SyncEXOFullAccessPermissionsToProductAssignments"
                executeApprovalActions = $false
            }
    
            [void]$obsoleteProductAssignmentObjects.Add($obsoleteProductAssignmentObject)
        }

        # Define assignments already existing
        $existingProductassignments = $currentProductassignments | Where-Object { $_.userGuid -in $productUsersInScope.userGuid }
        foreach ($existingProductassignment in $existingProductassignments) { 
            $existingProductAssignmentObject = [PSCustomObject]@{
                productGuid            = "$($product.productId)"
                productName            = "$($product.name)"
                userGuid               = "$($existingProductassignment.userGuid)"
                userName               = "$($existingProductassignment.userName)"
                source                 = "SyncEXOFullAccessPermissionsToProductAssignments"
                executeApprovalActions = $false
            }
    
            [void]$existingProductAssignmentObjects.Add($existingProductAssignmentObject)
        }

        # Define total assignments (existing + new assignments)
        $totalProductAssignments = ($(($existingProductAssignmentObjects | Measure-Object).Count) + $(($newProductAssignmentObjects | Measure-Object).Count))
    }
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error calculating new and obsolete product assignments. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Summary]------"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Product(s) in scope [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) already exist (and won't be changed) [$(($existingProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) to grant [$(($newProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "Total HelloID Self service Productassignment(s) to revoke [$(($obsoleteProductAssignmentObjects | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "------[Processing]------------------"
try {
    # Grant assignments
    $productAssigmentGrantsSuccess = 0
    $productAssigmentGrantsError = 0
    foreach ($newProductAssignmentObject in $newProductAssignmentObjects) {
        try {
            # if ($verboseLogging -eq $true) {
            #     Hid-Write-Status -Event Information -Message "Granting productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]""
            # }
        
            $body = @{
                userGuid               = "$($newProductAssignmentObject.userGuid)"
                source                 = "$($newProductAssignmentObject.source)"
                executeApprovalActions = $newProductAssignmentObject.executeApprovalActions
                comment                = "Synchronized assignment from EXO Full Access Permission"
            } | ConvertTo-Json

            $splatParams = @{
                Method      = "POST"
                Uri         = "product-assignment/$($newProductAssignmentObject.productGuid)"
                Body        = $body # ([System.Text.Encoding]::UTF8.GetBytes($body))
                ErrorAction = "Stop"
            }
            if ($dryRun -eq $false) {
                $grantProductassignmentToUser = Invoke-HIDRestMethod @splatParams
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "Successfully granted productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]"
                }
                $productAssigmentGrantsSuccess++
            }
            else {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "DryRun: Would grant productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]"
                }   
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            $productAssigmentGrantsError++
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Error -Message "Error granting productassignment for HelloID user [$($newProductAssignmentObject.username) ($($newProductAssignmentObject.userGuid))] to HelloID Self service Product [$($newProductAssignmentObject.productName) ($($newProductAssignmentObject.productGuid))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
    }
    if ($dryRun -eq $false) {
        if ($productAssigmentGrantsSuccess -ge 1 -or $productAssigmentGrantsError -ge 1) {
            Hid-Write-Status -Event Information -Message "Granted productassignments to HelloID Self service Products. Success: $($productAssigmentGrantsSuccess). Error: $($productAssigmentGrantsError)"
            Hid-Write-Summary -Event Information -Message "Granted productassignments to HelloID Self service Products. Success: $($productAssigmentGrantsSuccess). Error: $($productAssigmentGrantsError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would grant [$(($newProductAssignmentObjects | Measure-Object).Count)] productassignments for [$(($newProductAssignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Warning "DryRun: Would grant [$(($newProductAssignmentObjects | Measure-Object).Count)] productassignments for [$(($newProductAssignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
    }

    # Revoke assignments
    $productAssigmentRevokesSuccess = 0
    $productAssigmentRevokesError = 0
    foreach ($obsoleteProductAssignmentObject in $obsoleteProductAssignmentObjects) { 
        try {
            # if ($verboseLogging -eq $true) {
            #     Hid-Write-Status -Event Information -Message "Revoking productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]""
            # }
            
            $body = @{
                productGuid            = "$($obsoleteProductAssignmentObject.productGuid)"
                userGuid               = "$($obsoleteProductAssignmentObject.userGuid)"
                executeApprovalActions = $($obsoleteProductAssignmentObject.executeApprovalActions)
            } | ConvertTo-Json

            $splatParams = @{
                Method      = "POST"
                Uri         = "product-assignment/unassign/by-product"
                Body        = $body # ([System.Text.Encoding]::UTF8.GetBytes($body))
                ErrorAction = "Stop"
            }
            if ($dryRun -eq $false) {
                $revokeProductassignmentToUser = Invoke-HIDRestMethod @splatParams
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "Successfully revoked productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]"
                }
                $productAssigmentRevokesSuccess++
            }
            else {
                if ($verboseLogging -eq $true) {
                    Hid-Write-Status -Event Success -Message "DryRun: Would revoke productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]"
                }   
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            $productAssigmentRevokesError++
            if ($verboseLogging -eq $true) {
                Hid-Write-Status -Event Error -Message "Error revoking productassignment for HelloID user [$($obsoleteProductAssignmentObject.username) ($($obsoleteProductAssignmentObject.userGuid))] to HelloID Self service Product [$($obsoleteProductAssignmentObject.productName) ($($obsoleteProductAssignmentObject.productGuid))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
    }
    if ($dryRun -eq $false) {
        if ($productAssigmentRevokesSuccess -ge 1 -or $productAssigmentRevokesError -ge 1) {
            Hid-Write-Status -Event Information -Message "Revoked productassignments to HelloID Self service Products. Success: $($productAssigmentRevokesSuccess). Error: $($productAssigmentRevokesError)"
            Hid-Write-Summary -Event Information -Message "Revoked productassignments to HelloID Self service Products. Success: $($productAssigmentRevokesSuccess). Error: $($productAssigmentRevokesError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would revoke [$(($obsoleteProductassignmentObjects | Measure-Object).Count)] productassignments for [$(($obsoleteProductassignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Status -Event Warning -Message "DryRun: Would revoke [$(($obsoleteProductassignmentObjects | Measure-Object).Count)] productassignments for [$(($obsoleteProductassignmentObjects | Sort-Object -Property productGuid -Unique | Measure-Object).Count)] HelloID Self service Products"
    }

    if ($dryRun -eq $false) {
        Hid-Write-Status -Event Success -Message "Successfully synchronized [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Shared Mailbox Full Access Permissions to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "Successfully synchronized [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Shared Mailbox Full Access Permissions to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
    else {
        Hid-Write-Status -Event Success -Message "DryRun: Would synchronize [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Shared Mailbox Full Access Permissions to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
        Hid-Write-Summary -Event Success -Message "DryRun: Would synchronize [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Shared Mailbox Full Access Permissions to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    }
}
catch {
    Hid-Write-Status -Event Error -Message "Error synchronization of [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Shared Mailbox Full Access Permissions to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
    Hid-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Hid-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    Hid-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    Hid-Write-Summary -Event Failed -Message "Error synchronization of [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Shared Mailbox Full Access Permissions to [$totalProductAssignments] HelloID Self service Productassignments for [$(($helloIDSelfServiceProductsInScope | Measure-Object).Count)] HelloID Self service Products"
}
#endregion