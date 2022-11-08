######
###### REQUIREMENTS
###### 
###### Create a SelfSigned Certificate
###### Copy the cert.pem from the Ansible controller to the target host in C:\ before run the script
######


###### Enable PowerShell Remoting for Ansible WinRM
Set-Service -Name "WinRM" -StartupType Automatic
Start-Service -Name "WinRM"

if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {
    ## Use SkipNetworkProfileCheck to make available even on Windows Firewall public profiles
    ## Use Force to not be prompted if we're sure or not.
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
}


###### Enable Certificate-Based Authentication

Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

###### Create a Local User Account

$UserAccountName = 'winansibleuser' # This has to be the same user as the one configured in the certificate
$UserAccountPassword = (ConvertTo-SecureString -String 'VALUE' -AsPlainText -Force) # Password for user
if (-not (Get-LocalUser -Name $UserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $UserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $UserAccountPassword
    }
    $null = New-LocalUser @newUserParams
}


###### Import the Client Certificate

$pubKeyFilePath = 'C:\cert.pem'
## Import the public key into Trusted Root Certification Authorities and Trusted People
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\Root'
$null = Import-Certificate -FilePath $pubKeyFilePath -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople'

###### Create the Server Certificate

$hostname = hostname
$serverCert = New-SelfSignedCertificate -DnsName $hostName -CertStoreLocation 'Cert:\LocalMachine\My'

###### Create the Ansible WinRm Listener

$httpsListeners = Get-ChildItem -Path WSMan:\localhost\Listener\ | where-object { $_.Keys -match 'Transport=HTTPS' }

## If not listeners are defined at all or no listener is configured to work with
## the server cert created, create a new one with a Subject of the computer's host name
## and bound to the server certificate.
if ((-not $httpsListeners) -or -not (@($httpsListeners).where( { $_.CertificateThumbprint -ne $serverCert.Thumbprint }))) {
    $newWsmanParams = @{
        ResourceUri = 'winrm/config/Listener'
        SelectorSet = @{ Transport = "HTTPS"; Address = "*" }
        ValueSet    = @{ Hostname = $hostName; CertificateThumbprint = $serverCert.Thumbprint }
        # UseSSL = $true
    }
    $null = New-WSManInstance @newWsmanParams
}



###### “Map” the Client Certificate to the Local User Account

$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAccountName, $UserAccountPassword

## Find the cert thumbprint for the client certificate created on the Ansible host
$ansibleCert = Get-ChildItem -Path 'Cert:\LocalMachine\Root' | Where-Object {$_.Subject -eq 'CN=winansibleuser'}

$params = @{
	Path = 'WSMan:\localhost\ClientCertificate'
	Subject = "$UserAccountName@localhost"
	URI = '*'
	Issuer = $ansibleCert.Thumbprint
  Credential = $credential
	Force = $true
}
New-Item @params


###### Allow WinRm with User Account Control (UAC)


$newItemParams = @{
    Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Name         = 'LocalAccountTokenFilterPolicy'
    Value        = 1
    PropertyType = 'DWORD'
    Force        = $true
}
$null = New-ItemProperty @newItemParams


###### Open Port 5986 on the Windows Firewall


 $ruleDisplayName = 'Windows Remote Management (HTTPS-In)'
 if (-not (Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore)) {
     $newRuleParams = @{
         DisplayName   = $ruleDisplayName
         Direction     = 'Inbound'
         LocalPort     = 5986
         RemoteAddress = 'Any'
         Protocol      = 'TCP'
         Action        = 'Allow'
         Enabled       = 'True'
         Group         = 'Windows Remote Management'
     }
     $null = New-NetFirewallRule @newRuleParams
 }


###### Add the Local User to the Administrators Group

Get-LocalUser -Name $UserAccountName | Add-LocalGroupMember -Group 'Administrators'
