PARAM(
	[Parameter(Mandatory=$False)]
	[string[]]
	$Computername = $ENV:COMPUTERNAME,
	
	[Parameter(Mandatory=$True)]
	[string]
	[Alias("OldThumbprint","ReplaceCertificateThumbprint")]
	$ThumbprintToReplace,

	[Parameter(Mandatory=$True)]
	[string]
	$NewThumbPrint

) # PARAM

BEGIN { } # BEGIN

PROCESS {
	$ScriptBlock = {		# This script block is what is executed against remote nodes
		param(		
			[Parameter(Mandatory=$true,Position=0)]
            [string]
			$NewThumb,
			
			[Parameter(Mandatory=$true,Position=2)]
			[string]
			$CurrentThumb
		) # param
		
		Write-Host $ENV:COMPUTERNAME
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		
		Write-Host "Replacing cert with Thumbprint $CurrentThumb and updating to $NewThumb"
	
		
		if ( -not([string]::IsNullOrEmpty($currentThumb)) -and -not([string]::IsNullOrEmpty($newThumb) ) -and (Get-Module WebAdministration) ) {
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
		} # if ( -not([string]::IsNullOrEmpty($currentThumb)) )
		
	} # $ScriptBlock
	
	$ArgumentList = @($NewThumbPrint,  $ThumbprintToReplace)
	
	$InvokeParam = @{
		Computername = $Computername
		ScriptBlock = $ScriptBlock
		ArgumentList = $ArgumentList
	}

	Invoke-Command @InvokeParam
} # PROCESS

END {}
