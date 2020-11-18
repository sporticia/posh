# Functions to write red, yellow, green output messages
Function WriteBad
{
  Param([string]$ResultString)
  Write-Host -ForegroundColor Red $ResultString
}

Function WriteWarn
{
  Param([string]$ResultString)
  Write-Host -ForegroundColor Yellow $ResultString
}

Function WriteGood
{
  Param([string]$ResultString)
  Write-Host -ForegroundColor Green $ResultString
}

# Log everything we do to a log file
Function Writelog
{
  Param([string]$LogString)
  $Logfile = "$BaseDirectory\Logs\$(Get-Date -Format yyyyMMdd)-$Ref-log.txt"
  Add-Content -LiteralPath $LogFile -Value "$(Get-Date -Format yyyyMMdd-HH:mm:ss)--$Logstring `n`r"
}

# Log everything we do to a log file using UTC time
Function UTCWritelog
{
  Param([string]$LogString)
  $Logfile = "$BaseDirectory\Logs\$(Get-Date -Format yyyyMMdd)-<REF>-log.txt"
  Add-Content -LiteralPath $LogFile -Value "$(Get-UTCTimestamp)--$Logstring `n`r"
}

# Set date/time
Function Get-UTCTimestamp
{
  $Timestamp = [datetime]::UtcNow
  Return $Timestamp
}

# Get latest Windows OS
Function GetLatestOS
{
    $ImageName = (Get-AzureVMImage | Where-Object { $_.Label -like "*Server 2008 R2*"} | Sort-Object PublishedDate -Descending | Select-Object -ExpandProperty ImageName -First 1)
    Return $ImageName
}

# Get latest Windows OS (ARM)
Function GetLatestOS
{
    $ImageName = (Get-AzureRmVMImage -Location $Location -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2012-R2-Datacenter")
    $ImageName = ($ImageName | Sort-Object Version -Descending)
    $ImageName = $ImageName[0]
    Return $ImageName
}

# List Azure VM Images
Get-AzureVMImage | Where-Object {$_.Label -like "*<string>*"} | Select-Object Label
Get-AzureVMImage | Where-Object {($_.Label -like "*SQL Server 2016*") -and ($_.Label -like "*Server 2012 R2*")} | Select-Object Label

# Get Windows OS image (this gets latest 2016 with 127GB disk)
Function GetLatestOS
{
  $ImageName = (Get-AzureVMImage | Where-Object {($_.Label -like "*Windows-Server-2016-DataCenter*") -and ($_.Label -notlike "*SQL*") -and ($_.Label -notlike "*Core*") -and ($_.Label -notlike "*31GB*")} | Sort-Object PublishedDate -Descending | Select-Object -ExpandProperty ImageName -First 1)
  Return $ImageName
}

# Get SQL image (this gets SQL2016 on Server 2012 R2)
Function GetLatestSQL
{
  $ImageName = (Get-AzureVMImage | Where-Object { ($_.Label -like "*SQL Server 2016 RTM Enterprise*") } | Sort-Object PublishedDate -Descending | Select-Object -ExpandProperty ImageName -First 1)
  Return $ImageName
}

# Command Count
(Get-Command -Module Azure[RM]).Count

# Task scheduler arguments (quotes are required ! any space will need single quotes around them)
-Executionpolicy bypass -Noninteractive -NoProfile -Command "& { }"
-Executionpolicy bypass -Noninteractive -NoProfile -File <filename>

# Make secret srting
Function New-Secret
{
  $Bytes = New-Object Byte[] 32
  $Rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  $Rand.GetBytes($Bytes)
  $Rand.Dispose()
  $NewClientSecret = [System.Convert]::ToBase64String($Bytes)
  Return $NewClientSecret
}
# (This command will provide you with the new secret.  Please record it because you will not be able to get it again)
New-Secret

# Make random string
Function RandomString
{
  Param (
    [Parameter(Mandatory=$True)]
    [ValidateRange(8,24)]
    [Int]$StrLength
  )
  # Add numbers
  $Digits = 48..57
  # Add uppercase letters
  $UpperLetters = 65..90
  # Add uppercase letters
  $LowerLetters = 97..122
  # Add safe non alphanumerics
  $NonAlphaNumerics = 32..47
  # Make random string by taking a random char and appending it to $TmpStr for the total length supplied
  $RNDString = Get-Random -Count 10 -Input ($Digits + $UpperLetters + $LowerLetters + $NonAlphaNumerics) | ForEach-Object -Begin { $TmpStr = $null } -Process {$TmpStr += [char]$_} -End {$TmpStr}
  Return $RNDString
}

<#
openssl rand -base64 32
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
#>

# Create secure creds
Function New-Encrypted-Password
{
  Param (
    [String][Parameter(Mandatory=$true)]$PlainTextPasswd,
    [String][Parameter(Mandatory=$true)]$OutputPath
  )
  #To encrypt a password and save in to a file
  $Username = "test"
  $PlainTextPasswd | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File $OutputPath
  $SecurePasswd = Get-Content $OutputPath | ConvertTo-SecureString
  $MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, (Get-Content $OutputPath | ConvertTo-SecureString)
}

# Get secure password back (need to run under same user that encrypted the password)
Function Get-Decrypted-Password
{
  Param (
    [String]$EncryptedPasswdFile,
    [String]$Username
  )
  If(Test-Path $EncryptedPasswdFile)
  {
    $MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, (Get-Content $EncryptedPasswdFile | ConvertTo-SecureString)
    $Passwd = ($MyCredential).GetNetworkCredential().Password
    Return $Passwd
  }
  Else
  {
    Writelog $LogFile  "Can't find file with encrypted password in the $EncryptedPasswdFile location."
  }
}

Function Send-MailgunMsg
{
  Param
  (
    [Parameter(Mandatory=$True,Position=1)]
    [Array]$To,
    [String]$Subject = "Subject",
    $HTML
  )
  $From = "IT Messages <powershell@org.com>"
  $To = $To -join "&To="
  $APIKEy = "key-somekey"
  $API = "https://api.mailgun.net/v2/oerg.com/messages"
  $SecurePwd = ConvertTo-SecureString $APIKEy -AsPlainText -Force
  $Credential = New-Object System.Management.Automation.PSCredential ("api", $SecurePwd)
  $APICall = "$($API)?from=$($from)&to=$($to)&text=$($text)&subject=$($subject)"
  Invoke-RestMethod -Uri $APICall -Credential $Credential -Method Post
}

Function Get-AADToken
{
  [CmdletBinding()]
  [OutputType([String])]
  Param
  (
    [Parameter(Position=0,Mandatory=$true)]
    [ValidateScript({
          try
          {
            [System.Guid]::Parse($_) | Out-Null
            $true
          }
          catch
          {
            $false
          }
    })]
    [Alias('tID')]
    [String]$TenantID,

    [Parameter(Position=1,Mandatory=$true)][Alias('cred')]
    [pscredential]
    [System.Management.Automation.CredentialAttribute()]
    $Credential,

    [Parameter(Position=0,Mandatory=$false)][Alias('type')]
    [ValidateSet('UserPrincipal', 'ServicePrincipal')]
    [String]$AuthenticationType = 'UserPrincipal'
  )
  Try
  {
    $Username = $Credential.Username
    $Password = $Credential.Password

    If ($AuthenticationType -ieq 'UserPrincipal')
    {
      # Set well-known client ID for Azure PowerShell
      $clientId = 'clientId'

      # Set Resource URI to Azure Service Management API
      $resourceAppIdURI = 'https://management.azure.com/'

      # Set Authority to Azure AD Tenant
      $authority = 'https://login.microsoftonline.com/common/' + $TenantID
      Write-Verbose "Authority: $authority"

      $AADcredential = [Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential]::new($UserName, $Password)
      $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority)
      $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$AADcredential)
      $Token = $authResult.Result.CreateAuthorizationHeader()
    }
    else
    {
      # Set Resource URI to Azure Service Management API
      $resourceAppIdURI = 'https://management.core.windows.net/'

      # Set Authority to Azure AD Tenant
      $authority = 'https://login.windows.net/' + $TenantId

      $ClientCred = [Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential]::new($UserName, $Password)
      $authContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]::new($authority)
      $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$ClientCred)
      $Token = $authResult.Result.CreateAuthorizationHeader()
    }
  }
  Catch
  {
    Throw $_
    $ErrorMessage = 'Failed to aquire Azure AD token.'
    Write-Error -Message $ErrorMessage
  }
  $Token
}

Function Get-AAD-Token($appSpnId, $appSPnPassword)
{
  $url = "https://login.microsoftonline.com/<tenant_id>/oauth2/token"
  $body = @{'grant_type' = 'client_credentials'; 'client_id' = $appSPnId; 'client_secret' = $appSPnPassword; 'resource' = 'https://management.core.windows.net/'}
  $response = Invoke-WebRequest -Method POST -UseBasicParsing -Uri $url -Body $body
  return ($response.Content | ConvertFrom-Json).access_token
}

# Get Azure token
$Token = ((Login-AzureRmAccount).Context.TokenCache.ReadItems() | Sort-Object -Property ExpiresOn -Descending)[0].AccessToken

Function Login-and-Select-Subs($SpnUser, $SpnPassowrd, $Subscription )
{

  If (!(([string]::IsNullOrEmpty($SpnUser)) -or ([string]::IsNullOrEmpty($SpnPassowrd))))
  {
      $ProgressPreference = "SilentlyContinue"
      $spn = [PSCredential]::new("$SpnUser", (ConvertTo-SecureString "$SpnPassowrd" -AsPlainText -Force))
      Login-AzureRmAccount -ServicePrincipal -Credential $spn -TenantId "<tenant_id>"

      #Select subscription
      Write-Host "Selecting $subscription"
      Select-AzureRmSubscription -SubscriptionName $subscription
  }
  Else
  {
      Write-Host "User id or password is missing, please check"
      #exit 1
  }
}

# Find Group Policies with Missing Permissions
Function Get-GPMissingPermissionsGPOs
{
   $MissingPermissionsGPOArray = New-Object System.Collections.ArrayList
   $GPOs = Get-GPO -all
   foreach ($GPO in $GPOs)
   {
      If ($GPO.User.Enabled)
      {
        $GPOPermissionForAuthUsers = Get-GPPermission -Guid $GPO.Id -All | Select-Object -ExpandProperty Trustee | Where-Object {$_.Name -eq "Authenticated Users"}
        $GPOPermissionForDomainComputers = Get-GPPermission -Guid $GPO.Id -All | Select-Object -ExpandProperty Trustee | Where-Object {$_.Name -eq "Domain Computers"}
        If (!$GPOPermissionForAuthUsers -and !$GPOPermissionForDomainComputers)
        {
          $MissingPermissionsGPOArray.Add($GPO) | Out-Null
        }
      }
    }
    If ($MissingPermissionsGPOArray.Count -ne 0)
    {
      Write-Warning  "The following Group Policy Objects do not grant any permissions to the 'Authenticated Users' or 'Domain Computers' groups:"
      Foreach ($GPOWithMissingPermissions in $MissingPermissionsGPOArray)
      {
        Write-Host "'$($GPOWithMissingPermissions.DisplayName)'"
      }
    }
    Else
    {
      Write-Host "All Group Policy Objects grant required permissions. No issues were found." -ForegroundColor Green
    }
}

Function Wait-Process
{
  [OutputType([void])]
  [CmdletBinding()]
  Param
  (
    [Parameter(Mandatory=$True)]
    [String]$ProcessName
  )
  # Wait for all $ProcessName processes to complete/end before running
  $Running = $true;
  $TimeOut = 180 ## seconds
  $RetryInterval = 10 ##seconds

  Try
  {
    # Start counting
    $Timer = [Diagnostics.Stopwatch]::StartNew()

    # Keep looping until number of 'msiexec' processes goes to zero or timeout and continue after 3mins
    While (($Timer.Elapsed.TotalSeconds -lt $Timeout) -and ($Running -eq $true))
    {
      $Running = ((Get-Process | Where-Object ProcessName -ilike "*$ProcessName*").Length -gt 0)
      Write-Host "Process count for $ProcessName is " ((Get-Process | Where-Object ProcessName -ilike "*$ProcessName*").Length)
      Start-Sleep -Seconds $RetryInterval
      $TotalSecs = [math]::Round($Timer.Elapsed.TotalSeconds,0)
      Write-Host "Seconds so far $TotalSecs seconds"
    }

    # Stop counting
    $Timer.Stop()

    # Return status of what happened
    If ($Timer.Elapsed.TotalSeconds -gt $Timeout)
    {
      Throw 'Action timed out'
    }
    Else
    {
      Write-Verbose -Message 'All processes stopped after $TotalSecs seconds'
    }
  }
  Catch
  {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
  }
}


#Check Available IP addresses
$SubscriptionName = ""
Select-AzureSubscription -SubscriptionName $SubscriptionName
Get-AzureRmSubscription -SubscriptionName $SubscriptionName | Set-AzureRmContext
$VnetName = "some_vnet"
$networkID = "192.168.10."
For ($i=32; $i -lt 63; $i++)
{
    $IP = $networkID + $i
    $Address = Test-AzureStaticVNetIP -VNetName $VnetName -IPAddress $IP
    If ($Address.IsAvailable –eq $False) { Write-Host "$IP is not available" -ForegroundColor Red } else { Write-Host "$IP is available" -ForegroundColor Green}
}

Connect-AzureAD
Get-AzureADObjectByObjectId -ObjectIds "<object_id>"


using namespace System.Security.Cryptography.X509Certificates

#Exports the private key of a PFX file in DER / Binary format, converted into a base64 string
function Get-PrivateKey([Parameter(Mandatory)][String]$PFXFile, [Parameter(Mandatory)][SecureString]$Password) {
    $Certificate = [X509Certificate2]::new($PFXFile, $Password, [X509KeyStorageFlags]::Exportable);
    Write-Output "Thumbprint: $($Certificate.Thumbprint)`n"
    if ($Certificate.HasPrivateKey) {
        return [Convert]::ToBase64String($Certificate.PrivateKey.ExportCspBlob($true));
    }
    else {
        Write-Output "PFX file does not contain Private Key";
    }
}


# Example Usage:
#Get-PrivateKey -PFXFile "c:\certificate.pfx" -Password (ConvertTo-SecureString -Force -AsPlainText "password")
#Get-PrivateKey


<#$queue = [system.collections.queue]::new(@('\\server1\path','\\server2\path','\\server3\path'))
$sourcepath = 'c:\mysource'
while($queue.count -ne 0)
{
    robocopy $sourcepath $($queue.dequeue()) /s /e /MT
}#>

# Check number of versions of a powershell module that are installed
#Get-childitem 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -Depth 0 -Directory | ForEach-Object {Write-Host $_.Name (Get-ChildItem $_.FullName).Count}

# Check RBAC rights
#Get-AzureRmRoleAssignment -Scope "/subscriptions/9c255757-a7c8-4c88-8476-0d7bf926dd6a/resourcegroups/csre_storage-rg-nonprd-wr/providers/Microsoft.Storage/storageAccounts/gzpaycomnonprd01" -ObjectId bfcfffcd-51d0-43ed-a976-605e0ef5d543

# List TeamCity Nuget packages
#((Find-Package -Source https://teamcity.worldremit.com/guestAuth/app/nuget/v1/FeedService.svc).Name)


<# Powershell storage stuff
get-physicaldisk -CanPool $true

$sp = get-storagepool -FriendlyName "DataPool"
get-storagepool -FriendlyName "DataPool" | Get-PhysicalDisk
get-storagepool -FriendlyName "DataPool" | Get-VirtualDisk

$MyDisk = Get-PhysicalDisk -FriendlyName "PhysicalDisk9" -CanPool $true
Add-PhysicalDisk -PhysicalDisks $MyDisk -StoragePoolFriendlyName "DataPool"
Remove-PhysicalDisk -PhysicalDisks $MyDisk -StoragePoolFriendlyName "DataPool"

get-virtualdisk -FriendlyName "DataDisk" | Get-Disk
get-virtualdisk -FriendlyName "DataDisk" | Get-StoragePool
get-virtualdisk -FriendlyName "DataDisk" | Fl NumberOfColumns

get-virtualdisk -FriendlyName "DataDisk" | Resize-VirtualDisk -Size 3.99TB
Get-VirtualDisk "DataDisk" | Get-Disk | Get-Partition | Get-Volume
#>

# Support casee URL
# https://portal.azure.com/#resource/subscriptions/<id>/providers/microsoft.support/supporttickets/

# https://management.azure.com/subscriptions/{subscription-id}/providers/{provider-name}?&api-version={api-version}
# ((Get-AzureRmResourceProvider -ProviderNamespace Microsoft.Authorization).ResourceTypes | Where-Object ResourceTypeName -eq locks).ApiVersions
# ((Get-AzureRmResourceProvider -ProviderNamespace Microsoft.ServiceBus).ResourceTypes | Where-Object ResourceTypeName -eq namespaces).ApiVersions

# git checkout -b <branch>
# git branch -r
# git branch -r --merged
# git push --all --prune --dry-run
# git remote prune origin --dry-run

# VPX CLI add .pfx cert
# add ssl certkey <certname> -cert /nsconfig/ssl/<certfile>.pfx -key /nsconfig/ssl/<certfile>.pfx -password <password>

# Umbraco check for dupliacte property aliases
<#SELECT cct.[alias], [contentTypeId], cpt.[alias], count(cpt.[Alias])
FROM [cmsPropertyType] cpt JOIN [cmsContentType] cct on cpt.contentTypeId = cct.nodeId
GROUP BY cct.[alias], [contentTypeId], cpt.[alias]
HAVING COUNT(cpt.[alias]) > 1#>


#nginx -V (list compile time options)
#nginx -V 2>&1 | tr -- - '\n' | grep module


# Upload .pfx file to /flash/nsconf/ssl/
# add ssl certkey <certname> -cert /nsconfig/ssl/<certfile>.pfx -key /nsconfig/ssl/<certfile>.pfx -password <password>

# Fault tolderant curl attempts
# curl --retry 3 --retry-delay 5 --fail -sSL -o

# Select version from list with * (or any specified selector cahracter)
# cat <file> | grep '*' | tr -d '*'