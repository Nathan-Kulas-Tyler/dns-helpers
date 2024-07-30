[CmdletBinding(DefaultParameterSetName="NonSecure")]
PARAM(
	[Parameter(Mandatory=$False, ParameterSetName="NonSecure")]
	[Parameter(Mandatory=$False, ParameterSetName="Secure")]
	[string[]]
	$Computername = $ENV:COMPUTERNAME,
	
	[Parameter(Mandatory=$True, ParameterSetName="NonSecure")]
	[Parameter(Mandatory=$True, ParameterSetName="Secure")]
	[string]
	[Alias("FilePath")]
	$CertFilePath,
	
	[Parameter(Mandatory=$True, ParameterSetName="NonSecure")]
	[Parameter(Mandatory=$True, ParameterSetName="Secure")]
	[string]
	[Alias("OldThumbprint","ThumbprintToReplace")]
	$ReplaceCertificateThumbprint,
	
	[Parameter(Mandatory=$True, ParameterSetName="NonSecure")]
	[string]
	[Alias("Password")]
	$CertPassword,
	
	[Parameter(Mandatory=$True, ParameterSetName="Secure")]
	[ValidateNotNullOrEmpty()]
    [Security.SecureString]
	[Alias("SecurePassword")]
	$SecureCertPassword,
	
	[switch]
	$RemoveOldCert
) # PARAM

BEGIN {
	if ( $PSCmdlet.ParameterSetName -eq "NonSecure" ) {
		$SecureCertPassword = $CertPassword | ConvertTo-SecureString -AsPlainText -Force
	} # if ( $PSCmdlet.ParameterSetName -eq "NonSecure" )
} # BEGIN

PROCESS {
	$ScriptBlock = {		# This script block is what is executed against remote nodes
		param(		
			[Parameter(Mandatory=$true,Position=0)]
            [string]
			$EncodedCertificate,
			
			[Parameter(Mandatory=$false,Position=1)]
			[System.Security.SecureString]
            $Password = $null,
			
			[Parameter(Mandatory=$true,Position=2)]
			[string]
			$currentThumb,
			
			[switch]
			$RemoveOldCert
		) # param
		
		Write-Host $ENV:COMPUTERNAME
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		
		Write-Host "Replacing expired cert with Thumbprint $currentThumb"
		$certFilePath = Join-Path -Path $ENV:TEMP -ChildPath ([IO.Path]::GetRandomFileName())
		
		try {
			$certBytes = [Convert]::FromBase64String( $EncodedCertificate )
			[IO.File]::WriteAllBytes( $certFilePath, $certBytes )

			Write-Host "Importing new cert..."
			$newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
			$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
			$newCert.Import($certFilePath,$Password,$flags)
			$newThumb = $newCert.Thumbprint

			$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "My","LocalMachine"
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::"ReadWrite")
			$store.Add($newCert)
			$store.Close()
		} # try
		catch {
			throw $_
		}
		finally {
			Remove-Item -Path $certFilePath -ErrorAction SilentlyContinue
		} # finally
		
		
		if ( -not([string]::IsNullOrEmpty($currentThumb)) -and -not([string]::IsNullOrEmpty($newThumb) ) -and (Get-Module WebAdministration) ) {
			$currentCert = Get-ChildItem cert:\LocalMachine\ -recurse | Where-Object { $_.Thumbprint -match $currentThumb }
		
			Write-Host "New thumbprint is $newThumb"

			$BindingsToReplace = Get-WebBinding | Where-Object { $_.certificateHash -eq $currentThumb }
			ForEach ( $Binding in $BindingsToReplace ) {
				$sitename = $Binding.ItemXPath -replace '(?:.*?)name=''([^'']*)(?:.*)', '$1'
				$Header = $Binding.bindinginformation
				
				try {
					$Binding.RemoveSslCertificate()
					$Binding.AddSslCertificate($newThumb,"MY")
					Write-Output "$($ENV:COMPUTERNAME): Replaced $sitename $Header $($Binding.certificateHash) with $newThumb"
				}
				catch {
					Write-Output "$($ENV:COMPUTERNAME): Error replacing $sitename $Header $($Binding.certificateHash) with $newThumb"
				}
			}
			<#
			$BindingsToReplace = Get-ChildItem IIS:\SslBindings | Where-Object { $_.Thumbprint -eq $currentThumb }

			ForEach ( $binding in $BindingsToReplace ) {
				if ( $binding -eq $null ) {
					continue
				}  # if ( $binding -eq $null ) 
				
				Write-Host "Replacing binding..."
				$binding
				$SiteName = $binding.Sites.Value
				$HostHeader = $binding.Host
				
				if ( [string]::IsNullOrEmpty($SiteName) ) {
					# Sometimes the site name from the existing binding is blank - default it to "Default Web Site"
					$SiteName = "Default Web Site"
				} # if ( [string]::IsNullOrEmpty($SiteName)
				
				$IPAddresses = @($binding.IPAddress | select-object -expandproperty IPAddressToString)
				if ( $IPAddresses.count -eq 0) {
					$IPAddresses = '0.0.0.0'
				}
				$Port = $binding.Port

				$BindingName = $binding.PSChildName
				
				Push-Location IIS:\SslBindings\
				ForEach ( $IPAddress in $IPAddresses ) {
					$NewBindingParam = @{
						Port = $Port
						Name = $SiteName
						Protocol = "https"
						ErrorAction = "SilentlyContinue"
					}
					if ( $IPAddress -eq "0.0.0.0" ) {
						Write-Host "Creating new web binding $SiteName * $Port"
						#New-WebBinding -Name "$SiteName" -IP "*" -Port $Port -Protocol https -ErrorAction SilentlyContinue
						[void]$NewBindingParam.Add("IPAddress","*")
					} # if ( $IPAddress -eq "0.0.0.0" )
					else {
						Write-Host "Creating new web binding $SiteName $IPAddress $Port"
						#New-WebBinding -Name "$SiteName" -IP "$IPAddress" -Port $Port -Protocol https -ErrorAction SilentlyContinue
						[void]$NewBindingParam.Add("IPAddress",$IPAddress)
					} # else

					if (-not [string]::IsNullOrEmpty($HostHeader) ) {
						[void]$NewBindingParam.Add("HostHeader",$HostHeader)
					}

					if ( -not(Get-WebBinding @NewBindingParam) ) {
						New-WebBinding @NewBindingParam
					}
					
					
					$CurrentBindingName = $IPAddress + "!" + $Port
					
					if ( test-path -path $BindingName ) {
						Write-Host "Removing old binding $BindingName"
						Get-Item $BindingName
						Get-Item $BindingName | Where-Object { $_.Thumbprint -eq $currentThumb } | Remove-Item # $BindingName
					} # if ( test-path -path $BindingName )
					#elseif ( Test-Path $binding.PSChildName ) {
					#	Write-Host "Removing old binding $($binding.PSChildName)"
					#	Get-Item $binding.PSChildName
					#	Remove-Item $binding.PSChildName
					#}

					if ( -not(test-path -path $CurrentBindingName) ) {
						Write-Host "Creating binding $CurrentBindingName"
						Write-Host "Get-Item cert:\LocalMachine\MY\${newThumb} | New-Item $CurrentBindingName"
						Get-Item cert:\LocalMachine\MY\${newThumb} | New-Item $CurrentBindingName
					}
					
					
				} # ForEach ( $IPAddress in $IPAddresses )
				if ( -not(test-path -path $BindingName) ) {
					Write-Host "Creating binding $BindingName"
					Write-Host "Get-Item cert:\LocalMachine\MY\${newThumb} | New-Item $BindingName"
					try{Get-Item cert:\LocalMachine\MY\${newThumb} | New-Item $BindingName} catch {}
				}
				Pop-Location
			
			} # ForEach ( $binding in $BindingsToReplace )

			#>
			if ( $RemoveOldCert ) {
				ForEach ( $installedCert in $currentCert ) {
					$ParentDir = Split-Path $installedCert.PSParentPath -Leaf
					Write-Host "Deleting old cert $currentThumb from $ParentDir"
					$store = new-object System.Security.Cryptography.X509Certificates.X509Store $ParentDir,"LocalMachine"
					$store.Open("ReadWrite")
					$DeleteCert = $store.Certificates | Where-Object { $_.ThumbPrint -eq $currentThumb }
					$store.Remove($DeleteCert)
					$store.Close()
				} # ForEach ( $installedCert in $currentCert )
			}
			
		} # if ( -not([string]::IsNullOrEmpty($currentThumb)) )
		
	} # $ScriptBlock
	
	$bytes = [System.IO.File]::ReadAllBytes($CertFilePath)
	$encodedCert = [Convert]::ToBase64String( $bytes )

	$ArgumentList = @($encodedCert, $SecureCertPassword, $ReplaceCertificateThumbprint)
	if ( $RemoveOldCert ) {
		$ArgumentList += $RemoveOldCert
	}
	$InvokeParam = @{
		Computername = $Computername
		ScriptBlock = $ScriptBlock
		ArgumentList = $ArgumentList
	}
	# Invoke-Command -Computer $Computername -ScriptBlock $ScriptBlock -ArgumentList $encodedCert, $SecureCertPassword, $ReplaceCertificateThumbprint, $RemoveOldCert

	Invoke-Command @InvokeParam
} # PROCESS

END {}
