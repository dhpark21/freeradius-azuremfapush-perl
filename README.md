# Azure MFA for FreeRadius #

This tries to replicate the functionality of the [NPS MFA extension](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-nps-extension) on Windows Server.

## Configuration ##

There is a genral MS MFA CLientID. In order to use that with application permissions, a password must be created on the Service Principal within your directory.
The easiest way to do this is unfortunately Powershell. If you're an O365 admin, you will have it installed already:

````
Connect-MgGraph -Scopes 'Application.ReadWrite.All'
$servicePrincipalId = (Get-MgServicePrincipal -Filter "appid eq '981f26a1-7f43-403b-a875-f8b09b8cd720'").Id
$params = @{
	passwordCredential = @{
		displayName = "My Application MFA"
	}
}
$secret = Add-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipalId -BodyParameter $params

$secret
````

## Usage ##

Add **azure_mfa** to the authenticate section, e.g.

````
authenticate {
	Auth-Type PAP {
		pap
		azure_mfa
	}
}
````
