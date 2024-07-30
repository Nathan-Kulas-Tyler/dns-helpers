<#
.EXAMPLE
	.\Certificate\Find-SSRSServersWithCertificate.ps1  -ThumbPrint ABC00000000000000000000000123

#>

[CmdletBinding()]
PARAM(
	[Parameter(Mandatory=$True)]
	[string]
	$OldThumbPrint,

	[Parameter(Mandatory=$False)]
	[string]
	$NewThumbPrint,

	[Parameter(Mandatory=$False)]
	$Credential
) # PARAM

BEGIN {} # BEGIN

PROCESS {
	$Threshhold = [datetime]::now.AddDays(-14).Date.Tostring()
	$AllServers = Get-ADComputer -Prop * -Filter {LastLogonDate -gt $Threshhold -and objectClass -eq "computer"} | Select-Object -ExpandProperty DNSHostName
	$AllSsrsServers = New-Object System.Collections.ArrayList

	$OutputInterval = [math]::Round($AllServers.count / 10)
	$i = 0
	ForEach ( $Computer in $AllServers ) {
		if ( ($i % $OutputInterval) -eq 0 ) {
			Write-Host "Checking $($i + 1) of $($AllServers.length) servers for SSRS - this may take a few minutes."
		}
		$i++

		[array]$Output = Get-Service -ComputerName $Computer *rep* -ErrorAction SilentlyContinue | Where-Object {
			$_.DisplayName -match "SQL Server Reporting Services"
		} | Select-Object -ExpandProperty MachineName | Sort-Object -Unique

		if ( $Output.count -gt 0 ) {
			[void]$AllSsrsServers.Add($Output[0])
		}
	} # ForEach ( $Computer in $AllServers ) {

	$ScriptBlock = {		# This script block is what is executed against remote nodes
		param(		
			[Parameter(Mandatory=$true,Position=0)]
			[string]
			$OldThumbPrint,

			[Parameter(Mandatory=$false,Position=1)]
			[string]
			$NewThumbPrint
		) # param

		$SenderInfo = Get-Variable PSSenderInfo | Select-Object -expandproperty value
		$PSComputerName = $SenderInfo.ConnectionString.Split("/")[2].Split(":")[0]
		
		$ReturnObject = New-Object PSCustomObject -Prop @{
			Computer      = $PSComputerName
			$OldThumbprint  = $False
			$("{0}-SsrsBindings" -f $OldThumbPrint) = 0
			Comment       = ""
			AllThumbsInUse = ""
		}

		if ( $NewThumbprint ) {
			Add-Member -InputObject $ReturnObject -MemberType NoteProperty -Name $NewThumbprint -Value $False
			Add-Member -InputObject $ReturnObject -MemberType NoteProperty -Name $("{0}-SsrsBindings" -f $NewThumbprint) -Value 0
		}

		$currentCert = Get-ChildItem cert:\LocalMachine\ -recurse | Where-Object { $_.Thumbprint -match $OldThumbprint}
		if ( $CurrentCert ) {
			$ReturnObject.$($OldThumbprint) = $True
		}
		
		if ( $NewThumbPrint ) {
			$newCert = Get-ChildItem cert:\LocalMachine\ -recurse | Where-Object { $_.Thumbprint -match $NewThumbprint }
			if ( $newCert ) {
				$ReturnObject.$($NewThumbprint) = $True
			}
		}

		if ( $ReturnObject.$($NewThumbPrint) -or $ReturnObject.$($OldThumbprint) ) {
			$TRSServices = Get-Service | Where-Object {$_.Name -match "ReportServer" -and $_.Status -eq "Running"}
			$WmiServices = Get-WmiObject win32_service

			$AllThumbsInUse = New-Object System.Collections.ArrayList
			$AllThumbsInUseDetails = New-Object System.Collections.ArrayList

			$newcerthash = $NewThumbPrint.ToLower() #important
			$oldCertHash = $OldThumbprint.ToLower()

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
				
				$sslUrl = "https://+:443/"
				$lcid = 1033 # for english	
				
				# Retrieve the MSReportServer_ConfigurationSetting object
				$rsConfig = Get-WmiObject -class "MSReportServer_ConfigurationSetting" -namespace $InstanceNS -filter "InstanceName='$instance'" -ErrorAction SilentlyContinue
				
				$Bindings = $rsConfig.ListSSLCertificateBindings($lcid)
				#$InstanceNS
				#$Bindings
				if ( $Bindings.Length -gt 0 ) {
					$ThumbsInUse = $bindings.CertificateHash | Sort-Object -Unique
					ForEach ( $thumb in $ThumbsInUse) {
						if ( $AllThumbsInUse -notcontains $thumb ) {
							[void]$AllThumbsInUse.Add($thumb)
						}
						# Write-Host "$PSComputerName :: $($Bindings.Length) $thumb is being used on $instance"

						if ( $thumb -eq $oldCertHash ) {
							$ReturnObject.$("{0}-SsrsBindings" -f $OldThumbPrint) = $ReturnObject.$("{0}-SsrsBindings" -f $OldThumbPrint) + 1
						}

						if ( $thumb -eq $newcerthash ) {
							$ReturnObject.$("{0}-SsrsBindings" -f $NewThumbPrint) = $ReturnObject.$("{0}-SsrsBindings" -f $NewThumbPrint) + 1
						}
					}
				}
			}
			ForEach ( $_thumb in $AllThumbsInUse ) {
				$_cert = Get-ChildItem cert:\LocalMachine\ -recurse | Where-Object { $_.Thumbprint -match $_thumb} | Select-Object -First 1
				$ThumbFull = "{0} ({1}) Expires: {2}" -f $_cert.Subject, $_thumb, $_cert.NotAfter
				Write-Host "$PSComputerName :: $ThumbFull is in use"
				[void]$AllThumbsInUseDetails.Add($ThumbFull)
			}
			$ReturnObject.AllThumbsInUse = $AllThumbsInUseDetails
		}
		
		$ReturnObject
	} # $ScriptBlock
	
	$ArgumentList = @($OldThumbprint)

	$GenericReturnObject = New-Object PSCustomObject -Prop @{
		Computer      = ""
		$OldThumbprint  = ""
		$("{0}-SsrsBindings" -f $OldThumbprint) = ""
		Comment       = ""
		AllThumbsInUse = ""
	}

	if ( $NewThumbprint ) {
		$ArgumentList += $NewThumbPrint
		Add-Member -InputObject	$GenericReturnObject -MemberType NoteProperty -Name $NewThumbprint -Value ""
		Add-Member -InputObject	$GenericReturnObject -MemberType NoteProperty -Name $("{0}-SsrsBindings" -f $OldThumbprint) -Value ""
	}

	$Params = @{
		ComputerName = $AllSsrsServers
		ScriptBlock = $ScriptBlock
		ArgumentList = $ArgumentList
		ErrorVariable = $AllErrors
		ErrorAction = "SilentlyContinue"
	}

	if ( $PSBoundParameters.ContainsKey("Credential") ) {
		$Params.Add("Credential", $Credential)
	}

	Write-Host "Starting remote connections to $($AllSsrsServers.count) SSRS identified servers to check cert status..."

	[System.Collections.ArrayList]$AllOutput = Invoke-Command @Params

	ForEach ( $CurrentError in $AllErrors) {
		$ReturnObject = $GenericReturnObject.Copy()
		$ReturnObject.Computer = $CurrentError.TargetObject
		$ReturnObject.Message  = "Error connecting"
		$AllOutput.Add($ReturnObject)
	}

	#$AllOutput | Where-Object { $_.$($OldThumbprint) -eq $True -or $_.$($NewThumbprint) -eq $True }

	Write-Host "The following systems have old thumprint installed and still have bindings:"
	$AllOutput | Where-Object { $_.$($("{0}-SsrsBindings" -f $OldThumbprint)) -gt 0 } | Select-Object -ExpandProperty Computer

	$FileName = "{0}-{1}-{2}.csv" -f $OldThumbPrint, $NewThumbPrint,  [datetime]::now.ToString("yyyyMMdd.HHmm")
	$AllOutput | Export-Csv -NoTypeInformation $FileName
	Write-Host -ForegroundColor Yellow "All output written to $FileName"

} # PROCESS

END {}
