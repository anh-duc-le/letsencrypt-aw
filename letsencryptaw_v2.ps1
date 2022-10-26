#######################################################################################
# Script that renews a Let's Encrypt certificate for an Azure Application Gateway
# Pre-requirements:
#      - Have a storage account in which the folder path has been created:
#        '/.well-known/acme-challenge/', to put here the Let's Encrypt DNS check files

#      - Add "Path-based" rule in the Application Gateway with this configuration:
#           - Path: '/.well-known/acme-challenge/*'
#           - Check the configure redirection option
#           - Choose redirection type: permanent
#           - Choose redirection target: External site
#           - Target URL: <Blob public path of the previously created storage account>
#                - Example: 'https://test.blob.core.windows.net/public'
#      - For execution on Azure Automation
#           - Import modules:
#               - 'Az.Accounts'
#               - 'Az.Network'
#               - 'Az.Storage'
#               - 'ACME-PS'
#               - 'ACMESharp'
#           - Give the AA Managed Identity access to the App Gateway and Storage Account.
#
#      UPDATE 2019-11-27
#      - Due to deprecation of ACMEv1, a new script is required to use ACMEv2.
#        The module to use is called ACME-PS.
#
#      UPDATE 2020-09-03
#      - Migrated to Az modules.
#        Following modules are needed now: Az.Accounts, Az.Network, Az.Storage
#
#      UPDATE 2022-10-26
#      - Added support for www domain.
#        Good starting-point for adding more domains.
#      - Use Managed Identity for connecting.
#      - Force the ACME Account Key create.
#      - Add foreach for looping through the ACME authorization challenges.
#      - Use Update-ACMEOrder instead of Update-Order.
#
#######################################################################################

Param(
    [string]$domain,
    [string]$wwwDomain,
    [string]$EmailAddress,
    [string]$STResourceGroupName,
    [string]$storageName,
    [string]$AGResourceGroupName,
    [string]$AGName,
    [string]$AGOldCertName
)

# Ensures that no login info is saved after the runbook is done
Disable-AzContextAutosave

# Log in as managed identity from the Runbook
Connect-AzAccount -Identity

# Create a state object and save it to the harddrive
$state = New-ACMEState -Path $env:TEMP
$serviceName = 'LetsEncrypt'

# Fetch the service directory and save it in the state
Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru;

# Get the first anti-replay nonce
New-ACMENonce $state;

# Create an account key. The state will make sure it's stored. Azure Automation needs -Force switch.
New-ACMEAccountKey $state -PassThru -Force;

# Register the account key with the acme service. The account key will automatically be read from the state
New-ACMEAccount $state -EmailAddresses $EmailAddress -AcceptTOS;

# Load an state object to have service directory and account keys available
$state = Get-ACMEState -Path $env:TEMP;

# It might be neccessary to acquire a new nonce, so we'll just do it for the sake of the example.
New-ACMENonce $state -PassThru;

# Create the identifier for the root DNS name
$rootIdentifier = New-ACMEIdentifier $domain

# Create the identifier for the www DNS name
$wwwIdentifier = New-ACMEIdentifier $wwwDomain

# Bundle the identifiers
$identifiers = @($rootIdentifier, $wwwIdentifier);

# Create the order object at the ACME service.
$order = New-ACMEOrder $state -Identifiers $identifiers;

# Fetch the authorizations for that order
$authorizations = @(Get-ACMEAuthorization -State $state -Order $order);

$storageAccount = Get-AzStorageAccount -ResourceGroupName $STResourceGroupName -Name $storageName

foreach ($authZ in $authorizations) {
    # Select a challenge to fullfill
    $challenge = Get-ACMEChallenge $state $authZ "http-01";

    # Inspect the challenge data
    $challenge.Data;

    # Create the file requested by the challenge
    $fileName = $env:TMP + '\' + $challenge.Token;
    Set-Content -Path $fileName -Value $challenge.Data.Content -NoNewline;

    $blobName = ".well-known/acme-challenge/" + $challenge.Token
    $ctx = $storageAccount.Context
    Set-AzStorageBlobContent -File $fileName -Container "public" -Context $ctx -Blob $blobName

    # Signal the ACME server that the challenge is ready
    $challenge | Complete-ACMEChallenge $state;
}

# Wait a little bit and update the order, until we see the states
while ($order.Status -notin ("ready", "invalid")) {
    Start-Sleep -Seconds 10;
    $order | Update-ACMEOrder $state -PassThru;
}

# We should have a valid order now and should be able to complete it
# Therefore we need a certificate key
$certKey = New-ACMECertificateKey -Path "$env:TEMP\$domain.key.xml";

# Complete the order - this will issue a certificate singing request
Complete-ACMEOrder $state -Order $order -CertificateKey $certKey;

# Now we wait until the ACME service provides the certificate url
while (-not $order.CertificateUrl) {
    Start-Sleep -Seconds 15
    $order | Update-ACMEOrder $state -PassThru
}

# As soon as the url shows up we can create the PFX
$password = ConvertTo-SecureString -String "Passw@rd123***" -Force -AsPlainText
Export-ACMECertificate $state -Order $order -CertificateKey $certKey -Path "$env:TEMP\$domain.pfx" -Password $password;

# Delete blob to check DNS
Remove-AzStorageBlob -Container "public" -Context $ctx -Blob $blobName

### RENEW APPLICATION GATEWAY CERTIFICATE ###
$appgw = Get-AzApplicationGateway -ResourceGroupName $AGResourceGroupName -Name $AGName
Set-AzApplicationGatewaySSLCertificate -Name $AGOldCertName -ApplicationGateway $appgw -CertificateFile "$env:TEMP\$domain.pfx" -Password $password
Set-AzApplicationGateway -ApplicationGateway $appgw