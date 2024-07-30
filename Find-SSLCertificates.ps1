<#
.EXAMPLE
	.\Find-SSLCertificates.ps1 -ComputerName my-vm-01,mv-vm-02 -ThumbPrint ABCCC00000000000000000000000000000123

#>

[CmdletBinding()]
PARAM(
	[Parameter(Mandatory=$False)]
	[string[]]
	$Computername = $ENV:COMPUTERNAME,
	
	[Parameter(Mandatory=$True)]
	[string]
	$ThumbPrint,

	[Parameter(Mandatory=$False)]
	$Credential
) # PARAM

BEGIN {} # BEGIN

PROCESS {
	$ScriptBlock = {		# This script block is what is executed against remote nodes
		param(		
			[Parameter(Mandatory=$true,Position=0)]
			[string]
			$ThumbPrint
		) # param
		
		$currentCert = Get-ChildItem cert:\LocalMachine\ -recurse | Where-Object { $_.Thumbprint -match $ThumbPrint }
		if ( $CurrentCert ) {
			$CertLocations = $( (($currentCert | Select-Object -expandproperty PSParentPath ).Split(":")[-1]) -Join "`n")
			$Installed = $True
		}
		else {
			$CertLocations = ""
			$Installed = $False
			New-Object PSCustomObject -Prop @{
				Computer      = $ENV:COMPUTERNAME
				Installed     = $Installed
				CertThumb     = $Thumbprint
				CertLocations = $CertLocations
				SiteName      = ""
				Bindings      = ""
				Message       = "$Thumbprint not installed"
			}
			exit
			
		}
		
		try {
			Import-Module WebAdministration -ErrorAction Stop
		}
		catch {
			New-Object PSCustomObject -Prop @{
				Computer      = $ENV:COMPUTERNAME
				Installed     = $Installed
				CertThumb     = $Thumbprint
				CertLocations = $CertLocations
				SiteName      = ""
				Bindings      = ""
				Message       = "IIS MODULE COULD NOT BE LOADED"
			}
			exit
		}
		
		[array]$Bindings =  Get-WebBinding | Where-Object { $_.certificateHash -eq $ThumbPrint }  | ForEach-Object {
			$name = $_.ItemXPath -replace '(?:.*?)name=''([^'']*)(?:.*)', '$1'
			$BindingInfo = "{0} protocol:{1} sslEnabled:{2}" -f $_.bindingInformation, $_.protocol, $($_.sslFlags -eq 1)
			New-Object psobject -Property @{
				Name = $name
				Binding = $BindingInfo
			}
		} | Group-Object -Property Name | Select-Object Name, @{n="Bindings";e={($_.Group | ForEach-Object { $_.Binding }) -join "`n"}} #-Wrap
		
		if ( $Bindings.Count -eq 0 ) {
			New-Object PSCustomObject -Prop @{
				Computer      = $ENV:COMPUTERNAME
				Installed     = $Installed
				CertThumb     = $Thumbprint
				CertLocations = $CertLocations
				SiteName      = ""
				Bindings      = ""
				Message       = "No Bindings"
			}
			exit
		}
	
		ForEach ( $binding in $Bindings ) {
			New-Object PSCustomObject -Prop @{
				Computer      = $ENV:COMPUTERNAME
				Installed     = $Installed
				CertThumb     = $Thumbprint
				CertLocations = $CertLocations
				SiteName      = $binding.name
				Bindings      = $binding.Bindings
				Message       = ""
			}
		} # ForEach ( $binding in $Bindings )	
	} # $ScriptBlock
	$Params = @{
		ComputerName = $Computername
		ScriptBlock = $ScriptBlock
		ArgumentList = $ThumbPrint
		ErrorVariable = $AllErrors
		ErrorAction = "SilentlyContinue"
	}

	if ( $PSBoundParameters.ContainsKey("Credential") ) {
		$Params.Add("Credential", $Credential)
	}
	Invoke-Command @Params
	ForEach ( $CurrentError in $AllErrors) {
		New-Object PSCustomObject -Prop @{
			Computer      = $CurrentError.TargetObject
			Installed     = ""
			CertThumb     = ""
			CertLocations = ""
			SiteName      = ""
			Bindings      = ""
			Message       = "Error connecting"
		}
	}
} # PROCESS

END {}
