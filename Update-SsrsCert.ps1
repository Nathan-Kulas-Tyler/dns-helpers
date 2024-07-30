PARAM (
	[Parameter(Mandatory=$False)]
	[string[]]
	$Computername = $ENV:COMPUTERNAME,
	
	[Parameter(Mandatory=$True)]
	[string]
	$OldThumb,
	
	[Parameter(Mandatory=$True)]
	[string]
	$NewThumb,
	
	[Parameter(Mandatory=$False)]
	[string]
	$ServiceName
)

BEGIN {}

PROCESS {
	Invoke-Command -Computername $Computername -ScriptBlock {
		PARAM (
			[Parameter(Mandatory=$True)]
			[string]
			$OldThumb,
			
			[Parameter(Mandatory=$True)]
			[string]
			$NewThumb,
			
			[Parameter(Mandatory=$False)]
			[string]
			$ServiceName
		)

		$currentCert = Get-ChildItem cert:\LocalMachine\ -recurse | Where-Object { $_.Thumbprint -match $NewThumb }
		if ( -not $currentCert ) {
			Write-Warning "Certificate matching $NewThumb is not installed - quitting."
			exit
		}

		try{#Get current running services
			$TRSServices = Get-Service | Where-Object {$_.Name -match "ReportServer" -and $_.Status -eq "Running"}
			if ( $ServiceName ) {
				$TRSServices = $TRSServices | Where-Object { $_.Name -eq $ServiceName }
			}
			}#debug
		catch{
		}
		#$TRSServices = Get-Service | Where-Object {$_.Name -eq "ReportServer`$TRSCTE4966" -and $_.Status -eq "Running"}

		#ReportServer$TRSCTE4966

		$WmiServices = Get-WmiObject win32_service

		foreach ($Service in $TRSServices) {
			#get full service path
			$ServicePath = $WmiServices | Where-Object {$_.name -eq $Service.Name }
			#parse out the version of SQL
			$TRSVersion = $ServicePath.Pathname.Split("\").Split(".")[2].Split("MRSC")[4]
			#parse out the instance
			$Instance = $ServicePath.Pathname.Split("\").Split(".")[3]
			#set variables
			$defname = "RS_{0}" -f $instance
			$rsversion = "v{0}" -f $trsversion	
			$wmiNameSpace = "root\Microsoft\SqlServer\ReportServer"
			
			#set instance
			$InstanceNS = "$($wmiNameSpace)\$($defname)\$($rsVersion)\Admin"		
			
			#get cert thumbprint
			$certhash = $NewThumb.ToLower() #important
			$oldCertHash = $OldThumb.ToLower()
			
			$sslUrl = "https://+:443/"
			$lcid = 1033 # for english	
			
			# Retrieve the MSReportServer_ConfigurationSetting object
			$rsConfig = Get-WmiObject -class "MSReportServer_ConfigurationSetting" -namespace $InstanceNS -filter "InstanceName='$instance'" -ErrorAction SilentlyContinue
			
			$Bindings = $rsConfig.ListSSLCertificateBindings($lcid)
			if ( $Bindings.CertificateHash -notcontains $oldCertHash ) {
				Write-Host "Skipping $Application because cert does not match $oldThumb"
				continue  #commented out to remediate existing
			}
			
			$i=0
			ForEach ( $Application in $Bindings.Application ) {
				
				$sslPort = $Bindings.Port[$i]
				$ipaddress = $Bindings.IPAddress[$i]
				if ( [string]::IsNullOrEmpty($sslPort) -or [string]::IsNullOrEmpty($ipaddress)) {
					Write-Host "sslPort and ipAddress not currently defined, defaulting to 443 and '::'"
					$sslPort = 443
					$ipAddress = '::'
				}
				#$rsconfig.RemoveURL($Application, $sslUrl, $lcid)	
				Write-Host "Removing cert $($Service.Name) $Application $oldcertHash $ipaddress $sslport $lcid"
				[void]$rsConfig.RemoveSSLCertificateBindings($Application, $oldcertHash, $ipaddress, $sslPort, $lcid)	
				#$rsConfig.ReserveURL($Application, $sslUrl, $lcid)
				Write-Host "Creating cert $($Service.Name) $Application $certHash $ipaddress $sslport $lcid"
				$createoutput = $rsConfig.CreateSSLCertificateBinding($Application, $certHash, $ipaddress, $sslPort, $lcid)
				if (![string]::IsNullOrEmpty($createoutput.Error)) {
					Write-Host $createoutput.Error
				}
				if ( $createoutput.Error -match "The existing binding uses a different certificate from the current request" ) {
					$netshoutput = netsh http show sslcert ipport=[::]:443 | Select-String -pattern $oldcerthash -Quiet
					if ( $netshoutput ) {
						write-host "Removing $oldcerthash with netsh"
						netsh http delete sslcert ipport=[::]:443
						start-sleep -seconds 3
						$createoutput = $rsConfig.CreateSSLCertificateBinding($Application, $certHash, $ipaddress, $sslPort, $lcid)
					}
				}
				$i++
			}
			
			Write-Host "Starting sleep"
			Start-Sleep -Seconds 20

			# Stop and Start SQL Server's Reporting Services to ensure changes take affect
			Write-Host "Stopping $instance"
			[void]$rsconfig.SetServiceState($false, $false, $false)
			Start-Sleep -Seconds 5
			Write-Host "Starting $instance"
			[void]$rsconfig.SetServiceState($true, $true, $true)
		}
	} -ArgumentList $OldThumb, $NewThumb, $ServiceName
}
