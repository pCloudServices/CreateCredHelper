###########################################################################
#
# NAME: Reset Cred File Helper
#
# AUTHOR:  Mike Brook<mike.brook@cyberark.com>, Assaf Miron<assaf.miron@cyberark.com>
#
# COMMENT: 
# Script will attempt to regenerate the local Applicative Cred File and Sync it in the Vault.
#
#
###########################################################################
[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("cyberark","ldap")]
    [string]$AuthType = "cyberark",
    [Parameter(Mandatory=$false)]
    [Switch]
    $SkipVersionCheck
)

$Host.UI.RawUI.WindowTitle = "Privilege Cloud CreateCredFile-Helper"
$Script:LOG_FILE_PATH = "$PSScriptRoot\_CreateCredFile-Helper.log"

# Script Version
$ScriptVersion = "1.8"

#region Writer Functions
$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
<# 
.SYNOPSIS 
	Method to log a message on screen and in a log file
.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type
.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
	param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[Bool]$WriteLog = $true,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose", "Success", "LogOnly")]
		[String]$type = "Info",
		[Parameter(Mandatory=$false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try{
		If([string]::IsNullOrEmpty($LogFile) -and $WriteLog)
		{
			# User wanted to write logs, but did not provide a log file - Create a temporary file
			$LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
			Write-Host "No log file path inputed, created a temporary file at: '$LogFile'"
		}
		If ($Header -and $WriteLog) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
		ElseIf($SubHeader -and $WriteLog) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
			Write-Host "------------------------------------" -ForegroundColor Magenta
		}
		
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		$msgToWrite = ""
		
		# Mask Passwords
		if($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			{($_ -eq "Info") -or ($_ -eq "LogOnly")} 
			{ 
				If($_ -eq "Info")
				{
					Write-Host $MSG.ToString() -ForegroundColor $(If($Header -or $SubHeader) { "Magenta" } Else { "Gray" })
				}
				$msgToWrite = "[INFO]`t$Msg"
				break
			}
			"Success" { 
				Write-Host $MSG.ToString() -ForegroundColor Green
				$msgToWrite = "[SUCCESS]`t$Msg"
				break
			}
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor Yellow
				$msgToWrite = "[WARNING]`t$Msg"
				break
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite = "[ERROR]`t$Msg"
				break
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite = "[DEBUG]`t$Msg"
				}
				break
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose -Msg $MSG
					$msgToWrite = "[VERBOSE]`t$Msg"
				}
				break
			}
		}

		If($WriteLog) 
		{ 
			If(![string]::IsNullOrEmpty($msgToWrite))
			{				
				"[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
			}
		}
		If ($Footer -and $WriteLog) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
	}
	catch{
		Throw $(New-Object System.Exception ("Cannot write message"),$_.Exception)
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Join-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Join-ExceptionMessage
{
<#
.SYNOPSIS
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
	param(
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
		  $e = $e.InnerException
		  $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}

#endregion


#region Check latest version
# Taken from https://github.com/AssafMiron/CheckLatestVersion

$Script:GitHubAPIURL = "https://api.github.com/repos"

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-ScriptLatestVersion
# Description....: Compare the current version and the online (GitHub) version
# Parameters.....: The online file URL, current Version, a pattern to look for the script version number in the online file
# Return Values..: True if the online version is the latest, False otherwise
# =================================================================================================================================
Function Test-ScriptLatestVersion
{
<# 
.SYNOPSIS 
	Compare the current version and the online (GitHub) version
.DESCRIPTION
	Compare the current version and the online (GitHub) version.
    Can compare version number based on Major, Major-Minor and Major-Minor-Patch version numbers
    Returns True if the online version is the latest, False otherwise
.PARAMETER fileURL
    The online file URL (in GitHub) to download and inspect
.PARAMETER currentVersion
    The current version number to compare to
.PARAMETER versionPattern
    A pattern of the script version number to search for in the online file
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]$fileURL,
        [Parameter(Mandatory=$true)]
        [string]$currentVersion,
        [Parameter(Mandatory=$false)]
        [string]$versionPattern = "ScriptVersion",
        [Parameter(Mandatory=$false)]
        [ref]$outGitHubVersion
    )
    $getScriptContent = ""
    $isLatestVersion = $false
    try{
        $getScriptContent = (Invoke-WebRequest -UseBasicParsing -Uri $scriptURL).Content
        If($($getScriptContent -match "$versionPattern\s{0,1}=\s{0,1}\""([\d\.]{1,10})\"""))
	    {
            $gitHubScriptVersion = $Matches[1]
            if($null -ne $outGitHubVersion)
            {
                $outGitHubVersion.Value = $gitHubScriptVersion
            }
            Write-LogMessage -type verbose -msg "Current Version: $currentVersion; GitHub Version: $gitHubScriptVersion"
            # Get a Major-Minor number format
            $gitHubMajorMinor = [double]($gitHubScriptVersion.Split(".")[0..1] -join '.')
            $currentMajorMinor = [double]($currentVersion.Split(".")[0..1] -join '.')
            # Check if we have a Major-Minor-Patch version number or only Major-Minor
            If(($gitHubScriptVersion.Split(".").count -gt 2) -or ($currentVersion.Split(".").count -gt 2))
            {
                $gitHubPatch = [int]($gitHubScriptVersion.Split(".")[2])
                $currentPatch = [int]($currentVersion.Split(".")[2])
            }
            # Check the Major-Minor version
            If($gitHubMajorMinor -ge $currentMajorMinor)
            {
                If($gitHubMajorMinor -eq $currentMajorMinor)
                {
                    # Check the patch version
                    $isLatestVersion = $($gitHubPatch -gt $currentPatch)
                }
                else {
                    $isLatestVersion = $true
                }
            }
        }
        else {
            Throw "Test-ScriptLatestVersion: Couldn't match Script Version pattern ($versionPattern)"
        }
	}
	catch
	{
		Throw $(New-Object System.Exception ("Test-ScriptLatestVersion: Couldn't download and check for latest version",$_.Exception))
	}
    return $isLatestVersion
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Copy-GitHubContent
# Description....: Copies all file and folder structure from a specified GitHub repository folder
# Parameters.....: The output folder path, the GitHub item URL to download from
# Return Values..: NONE
# =================================================================================================================================
Function Copy-GitHubContent
{
    <# 
.SYNOPSIS 
	Copies all file and folder structure from a specified GitHub repository folder
.DESCRIPTION
	Copies all file and folder structure from a specified GitHub repository folder
    Will create the content from a GitHub URL in the output folder
    Can handle files and folders recursively
.PARAMETER outputFolderPath
    The folder path to create the files and folders in
.PARAMETER gitHubItemURL
    The GitHub item URL to download from
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$outputFolderPath,
        [Parameter(Mandatory=$true)]
        [string]$gitHubItemURL
    )
    try{
        $gitHubFolderObject = (Invoke-RestMethod -Method Get -Uri $gitHubItemURL)
        foreach ($item in $gitHubFolderObject) {
            if($item.type -eq "dir")
            {
                # Create the relevant folder
                $itemDir = Join-Path -Path $outputFolderPath -ChildPath $item.name
                if(! (Test-Path -path $itemDir))
                {
                    New-Item -ItemType Directory -Path $itemDir | Out-Null
                }		
                # Get all relevant files from the folder
                Copy-GitHubContent -outputFolderPath $itemDir -gitHubItemURL $item.url
            }
            elseif ($item.type -eq "file") {
                Invoke-WebRequest -UseBasicParsing -Uri ($item.download_url) -OutFile $(Join-Path -Path $outputFolderPath -ChildPath $item.name)
            }
        }
    }
    catch{
        Throw $(New-Object System.Exception ("Copy-GitHubContent: Couldn't download files and folders from GitHub URL ($gitHubItemURL)",$_.Exception))
    }
}

Function Replace-Item
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$Destination,
        [Parameter(Mandatory=$false)]
        [switch]$Recurse
    )

    try{
        foreach($item in $(Get-ChildItem -Recurse:$Recurse -Path $Path))
        {
            $destPath = split-path -path $item.fullName.Replace($Path, $Destination) -Parent
            $oldName = "$($item.name).OLD"
            if(Test-Path -Path $(Join-Path -path $destPath -ChildPath $item.name))
            {
                Rename-Item -Path $(Join-Path -path $destPath -ChildPath $item.name) -NewName $oldName
                Copy-Item -path $item.FullName -Destination $(Join-Path -path $destPath -ChildPath $item.name)
                Remove-Item -path $(Join-Path -path $destPath -ChildPath $oldName)
            }
            Else
			{
				Write-Error "Can't find file $($item.name) in destination location '$destPath' to replace, copying"
                Copy-Item -path $item.FullName -Destination $destPath
			}
        }
    }
    catch{
        Throw $(New-Object System.Exception ("Replace-Item: Couldn't Replace files",$_.Exception))
    }

}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-GitHubLatestVersion
# Description....: Tests if the script is running the latest version from GitHub
# Parameters.....: NONE
# Return Values..: True / False
# =================================================================================================================================
Function Test-GitHubLatestVersion
{
<# 
.SYNOPSIS 
	Tests if the script is running the latest version from GitHub
.DESCRIPTION
	Tests if the script is running the latest version from GitHub
    Can support a mode of test only and Test and download new version
    Can support searching the entire repository or a specific folder or a specific branch (default main)
    If not exclusively selected to test only, the function will update the script if a new version is found
.PARAMETER repositoryName
    The repository name
.PARAMETER scriptVersionFileName
    The file name to search the script version in
.PARAMETER currentVersion
    The current version of the script
.PARAMETER sourceFolderPath
    The source folder of the script
    Used to download and replace the new updated script to
.PARAMETER repositoryFolderPath
    The repository Folder path
.PARAMETER branch
    The branch to search for
    Default main
.PARAMETER versionPattern
    The pattern to check in the script
    Default: ScriptVersion
.PARAMETER TestOnly
    Switch parameter to perform only test
    If not exclusively selected, the function will update the script if a new version is found
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$repositoryName,
    [Parameter(Mandatory=$true)]
    [string]$scriptVersionFileName,
    [Parameter(Mandatory=$true)]
    [string]$currentVersion,
    [Parameter(Mandatory=$true)]
    [string]$sourceFolderPath,
    [Parameter(Mandatory=$false)]
    [string]$repositoryFolderPath,
    [Parameter(Mandatory=$false)]
    [string]$branch = "main",
    [Parameter(Mandatory=$false)]
    [string]$versionPattern = "ScriptVersion",
    [Parameter(Mandatory=$false)]
    [switch]$TestOnly
)
    if([string]::IsNullOrEmpty($repositoryFolderPath))
    {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents"
    }
    else {
        $apiURL = "$GitHubAPIURL/$repositoryName/contents/$repositoryFolderPath`?ref=$branch"
    }
	
	$retLatestVersion = $true
	try{
		$folderContents = $(Invoke-RestMethod -Method Get -Uri $apiURL)
		$scriptURL = $($folderContents | Where-Object { $_.Type -eq "file" -and $_.Name -eq $scriptVersionFileName }).download_url
        $gitHubVersion = 0
        $shouldDownloadLatestVersion = Test-ScriptLatestVersion -fileURL $scriptURL -currentVersion $currentVersion -outGitHubVersion ([ref]$gitHubVersion)
	}
	catch
	{
		Throw $(New-Object System.Exception ("Test-GitHubLatestVersion: Couldn't check for latest version",$_.Exception))
	}
	
    try{
        # Check if we need to download the gitHub version
        If($shouldDownloadLatestVersion)
        {
            # GitHub has a more updated version
            $retLatestVersion = $false
            If(! $TestOnly) # Not Test only, update script
            {
                Write-LogMessage -type Info -Msg "Found new version (version $gitHubVersion), Updating..."
                # Create a new tmp folder to download all files to
                $tmpFolder = Join-Path -path $sourceFolderPath -ChildPath "tmp"
                if(! (Test-Path -path $tmpFolder))
                {
                    New-Item -ItemType Directory -Path $tmpFolder | Out-Null
                }
                try{
                    # Download the entire folder (files and directories) to the tmp folder
                    Copy-GitHubContent -outputFolderPath $tmpFolder -gitHubItemURL $apiURL
                    # Replace the current folder content
                    Replace-Item -Recurse -Path $tmpFolder -Destination $sourceFolderPath
                    # Remove tmp folder
                    Remove-Item -Recurse -Path $tmpFolder -Force
                }
                catch
                {
                    # Revert to current version in case of error
                    $retLatestVersion = $true
                    Write-Error -Message "There was an error downloading GitHub content." -Exception $_.Exception
                }
            }
            else {
                Write-LogMessage -type Info -Msg "Found a new version in GitHub (version $gitHubVersion), skipping update"    
            }
        }
        Else
        {
            Write-LogMessage -type Info -Msg "Current version ($currentVersion) is the latest!"
        }
    }
    catch
	{
		Throw $(New-Object System.Exception ("Test-GitHubLatestVersion: Couldn't download latest version",$_.Exception))
	}
	
	return $retLatestVersion
}
#endregion

#region Components Detection
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ServiceInstallPath
# Description....: Get the installation path of a service
# Parameters.....: Service Name
# Return Values..: $true
#                  $false
# =================================================================================================================================
# Save the Services List
$m_ServiceList = $null
Function Get-ServiceInstallPath
{
<#
  .SYNOPSIS
  Get the installation path of a service
  .DESCRIPTION
  The function receive the service name and return the path or returns NULL if not found
  .EXAMPLE
  (Get-ServiceInstallPath $<ServiceName>) -ne $NULL
  .PARAMETER ServiceName
  The service name to query. Just one.
 #>
	param ($ServiceName)
	Begin {

	}
	Process {
		$retInstallPath = $Null
		try{
			if ($null -eq $m_ServiceList)
			{
				Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
				#$m_ServiceList = Get-Reg -Hive "LocalMachine" -Key System\CurrentControlSet\Services -Value $null
			}
			$regPath =  $m_ServiceList | Where-Object {$_.PSChildName -eq $ServiceName}
			If ($Null -ne $regPath)
			{
				$retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'),$regPath.ImagePath.LastIndexOf('"')+1)
			}
		}
		catch{
			Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName",$_.Exception))
		}

		return $retInstallPath
	}
	End {

	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-FileVersion
# Description....: Method to return a file version
# Parameters.....: File Path
# Return Values..: File version
# =================================================================================================================================
Function Get-FileVersion
{
<#
.SYNOPSIS
	Method to return a file version

.DESCRIPTION
	Returns the File version and Build number
	Returns Null if not found

.PARAMETER FilePath
	The path to the file to query
#>
	param ($filePath)
	Begin {

	}
	Process {
		$retFileVersion = $Null
		try{
			If (($null -ne $filePath) -and (Test-Path $filePath))
			{
				$path = Resolve-Path $filePath
				$retFileVersion = ($path | Get-Item | Select-Object VersionInfo).VersionInfo.ProductVersion
			}
			else
			{
				throw "File path is empty"
			}

			return $retFileVersion
		}
		catch{
			Throw $(New-Object System.Exception ("Cannot get File ($filePath) version",$_.Exception))
		}
		finally{

		}
	}
	End {

	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Find-Components
# Description....: Detects all CyberArk Components installed on the local server
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Find-Components
{
<#
.SYNOPSIS
	Method to query a local server for CyberArk components
.DESCRIPTION
	Detects all CyberArk Components installed on the local server
#>
	param(
		[Parameter(Mandatory=$false)]
		[ValidateSet("All","CPM","PVWA","PSM","AIM")]
		[String]$Component = "All"
	)

	Begin {
		$retArrComponents = @()
		# COMPONENTS SERVICE NAMES
		$REGKEY_CPMSERVICE = "CyberArk Password Manager"
        $REGKEY_CPMScannerSERVICE = "CyberArk Central Policy Manager Scanner"
		$REGKEY_PVWASERVICE = "CyberArk Scheduled Tasks"
		$REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
		$REGKEY_AIMSERVICE = "CyberArk Application Password Provider"
	}
	Process {
		if(![string]::IsNullOrEmpty($Component))
		{
			Switch ($Component) {
				"CPM"
				{
					try{
						# Check if CPM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for CPM..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_CPMSERVICE)))
						{
							# Get the CPM Installation Path
							Write-LogMessage -Type "Info" -MSG "Found CPM installation"
							$cpmPath = $componentPath.Replace("Scanner\CACPMScanner.exe","").Replace("PMEngine.exe","").Replace("/SERVICE","").Replace('"',"").Trim()
                            $ConfigPath = (Join-Path -Path $cpmPath -ChildPath "Vault\Vault.ini")
							$fileVersion = Get-FileVersion "$cpmPath\PMEngine.exe"
                            $serviceLogsOldTrace = @(Join-Path -Path $cpmPath -ChildPath "Logs\old\PMTrace.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $serviceLogsOldConsole = @(Join-Path -Path $cpmPath -ChildPath "Logs\old\PMConsole.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $ServiceLogsMain = @((Join-Path -Path $cpmPath -ChildPath "Logs\PMTrace.log"),(Join-Path -Path $cpmPath -ChildPath "Logs\CACPMScanner.log"))
                            $serviceLogs = $ServiceLogsMain + $serviceLogsOldTrace + $serviceLogsOldConsole
                            #Create New Fresh Cred File, it will not overwrite an existing one, this is just incase there was no cred to begin with.
                            New-Item (Join-Path -Path $cpmPath -ChildPath "Vault\user.ini") -ErrorAction SilentlyContinue | Get-Acl | Set-Acl (Join-Path -Path $cpmPath -ChildPath "Vault\Vault.ini")
                            $appFilePath = (Join-Path -Path $cpmPath -ChildPath "Vault\user.ini")
                            if (Test-Path $appFilePath){
                                $ComponentUser = @($appFilePath)
                            }
							$myObject = New-Object PSObject -Property @{Name="CPM";DisplayName="CyberArk Password Manager (CPM)";
                                                                        ServiceName=@($REGKEY_CPMSERVICE,$REGKEY_CPMScannerSERVICE);Path=$cpmPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType } | Out-Null
                            return $myObject
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"PVWA"
				{
					try{
						# Check if PVWA is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for PVWA..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PVWASERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found PVWA installation"
							$pvwaPath = $componentPath.Replace("Services\CyberArkScheduledTasks.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe"
                            $ServiceLogs = @()
                            $ComponentUser = @()
                            $ConfigPath = ""
                            $myObject = New-Object PSObject -Property @{Name="PVWA";DisplayName="CyberArk Password Vault Web Application (PVWA)";
                                                                        ServiceName=$REGKEY_PVWASERVICE;Path=$pvwaPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType} | Out-Null
                            return $myObject
						}
					} catch {
                        Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"PSM"
				{
                    try{
                        # Check if PSM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for PSM..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_PSMSERVICE)))
						{
                            Write-LogMessage -Type "Info" -MSG "Found PSM installation"
							$PSMPath = $componentPath.Replace("CAPSM.exe","").Replace('"',"").Trim()
                            $ConfigPath = (Join-Path -Path $PSMPath -ChildPath "temp\PVConfiguration.xml")
							$fileVersion = Get-FileVersion "$PSMPath\CAPSM.exe"
                            $serviceLogsOldTrace = @(Join-Path -Path $PSMPath -ChildPath "Logs\old\PSMTrace.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $serviceLogsOldConsole = @(Join-Path -Path $PSMPath -ChildPath "Logs\old\PSMConsole.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $ServiceLogsMain = @(Join-Path -Path $PSMPath -ChildPath "Logs\PSMTrace.log")
                            $ServiceLogs = $ServiceLogsMain + $serviceLogsOldTrace + $serviceLogsOldConsole
                            $ComponentUser = @()
                            #Create New Fresh Cred File, it will not overwrite an existing one, this is just incase there was no cred to begin with.
                            foreach($cleanCredFile in @("psmapp.cred","psmgw.cred"))
                            {
                            New-Item (Join-Path -Path $PSMPath -ChildPath "Vault\$cleanCredFile") -ErrorAction SilentlyContinue | Get-Acl | Set-Acl (Join-Path -Path $PSMPath -ChildPath "Vault\Vault.ini")
                            }
                            foreach($fileName in @("psmapp.cred","psmgw.cred"))
                            {
                                $appFilePath = (Join-Path -Path $PSMPath -ChildPath "Vault\$fileName")
                                if (Test-Path $appFilePath){
                                    $ComponentUser += $appFilePath
                                }
                            }
                            $myObject = New-Object PSObject -Property @{Name="PSM";DisplayName="CyberArk Privileged Session Manager (PSM)";
                                                                        ServiceName=$REGKEY_PSMSERVICE;Path=$PSMPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType} | Out-Null
                            return $myObject
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"AIM"
				{
					try{
						# Check if AIM is installed
						Write-LogMessage -Type "Debug" -MSG "Searching for AIM..."
						if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $REGKEY_AIMSERVICE)))
						{
							Write-LogMessage -Type "Info" -MSG "Found AIM installation"
							$AIMPath = $componentPath.Replace("/mode SERVICE","").Replace("AppProvider.exe","").Replace('"',"").Trim()
							$fileVersion = Get-FileVersion "$AIMPath\AppProvider.exe"
                            $ComponentUser = @()
                            $ConfigPath = ""
                            $ServiceLogs = @()
                            $myObject = New-Object PSObject -Property @{Name="AIM";DisplayName="CyberArk Application Password Provider (AIM)";
                                                                        ServiceName=$REGKEY_AIMSERVICE;Path=$AIMPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType } | Out-Null
                            return $myObject
						}
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting $Component component. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
				"All"
				{
					try{
						ForEach($comp in @("CPM","PVWA","PSM","AIM"))
						{
							$retArrComponents += Find-Components -Component $comp
						}
						return $retArrComponents
					} catch {
						Write-LogMessage -Type "Error" -Msg "Error detecting components. Error: $(Join-ExceptionMessage $_.Exception)"
					}
					break
				}
			}
		}
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Set-PVWAURL
# Description....: Sets the PVWA URLs to be used in the script based on the Component found
# Parameters.....: Component ID (PVWA, CPM, PSM), ConfigPath
# Return Values..: NONE (All PVWA URLs are set on a script level)
# =================================================================================================================================
Function Set-PVWAURL{
<#
.SYNOPSIS
	Sets the PVWA URLs to be used in the script based on the Component found
.DESCRIPTION
	Sets the PVWA URLs to be used in the script based on the Component found
.PARAMETER ComponentID
    The component ID that is used
    Accepts only: PVWA, CPM, PSM
.PARAMETER ConfigPath
    For CPM and PSM, this is the configuration path to extract the PVWA URL from
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("PVWA","CPM","PSM")]
        [string]$ComponentID,
        [Parameter(Mandatory=$False)]
        [string]$ConfigPath,
        [Parameter(Mandatory=$False)]
        [ValidateSet("cyberark","ldap")]
        [string]$AuthType = "cyberark"
    )
    Try{
        $foundConfig = $false
        Write-LogMessage -type debug -Msg "Get PVWA URL from component '$ComponentID' and from config file '$ConfigPath'"
        if($ComponentID -eq "PVWA")
        {
            $PVWAurl = "https://$($env:COMPUTERNAME)"
            $foundConfig = $true
        }
        if (Test-Path $ConfigPath)
        {
            if ($ComponentID -eq "PSM"){
                [xml]$GetPVWAStringURL = Get-Content $ConfigPath
                if(![string]::IsNullOrEmpty($GetPVWAStringURL) -and $GetPVWAStringURL.PasswordVaultConfiguration.General.ApplicationRoot){ 
                    # In case there is more than one address, get the first one
                    $PVWAurl = ($GetPVWAStringURL.PasswordVaultConfiguration.General.ApplicationRoot).Split(",")[0]
                    # Check that the PVWAUrl contains a URL and not IP
                    $foundConfig = ($PVWAurl -NotMatch "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                }
                else {
                    Write-LogMessage -type Warning -Msg "Error reading the configuration file"
                }
            }
            if ($ComponentID -eq "CPM"){
                try{
                    # In case there is more than one address, get the first one
                    $GetPVWAStringURL = ((Get-Content $ConfigPath | Where-Object {$_ -match "Addresses" }).Split("=")[1]).Split(",")[0]
                } catch {
                    Write-LogMessage -type Error -MSG "There was an error finding PVWA Address from CPM configuration file"
                    $GetPVWAStringURL = $null
                }
                If(![string]::IsNullOrEmpty($GetPVWAStringURL)){
                    $PVWAurl = $GetPVWAStringURL
                    $foundConfig = $true
                }
            }
        }
        # We Couldn't find PVWA URL so we prompt the user
        if(($foundConfig -eq $False) -or ([string]::IsNullOrEmpty($PVWAurl)))
        {
            $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com')")
        }
        Write-LogMessage -type debug -Msg "The PVWA URL to be used is: '$PVWAurl'"
    } Catch{
        Throw $(New-Object System.Exception ("There was an error reading the $ComponentID configuration file '$ConfigPath'",$_.Exception))
    }
    
    # Set the PVWA URLS
    $URL_PVWA = "https://"+([System.Uri]$PVWAurl).Host
    $URL_PVWAPasswordVault = $URL_PVWA+"/passwordVault"
    $script:URL_PVWAAPI = $URL_PVWAPasswordVault+"/api"
    $URL_PVWAAuthentication = $URL_PVWAAPI+"/auth"
    $script:URL_PVWALogon = $URL_PVWAAuthentication+"/$AuthType/Logon"
    $script:URL_PVWALogoff = $URL_PVWAAuthentication+"/Logoff"
    Write-LogMessage -type debug -Msg "Logon URL will be: '$URL_PVWALogon'"
    # URL Methods
    # -----------
    $script:URL_Users = $URL_PVWAAPI+"/Users"
    $script:URL_UserResetPassword = $URL_Users+"/{0}/ResetPassword"
    $script:URL_UserActivate = $URL_Users+"/{0}/Activate"
    $script:URL_SystemHealthComponent =  $URL_PVWAAPI+"/ComponentsMonitoringDetails/"
    Write-LogMessage -type debug -Msg "Users URL will be: '$URL_Users'"
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-SystemHealth
# Description....: Detects all CyberArk Components installed on the local server
# Parameters.....: None
# Return Values..: Array of detected components on the local server
# =================================================================================================================================
Function Get-SystemHealth
{
    param(
        # Component ID to return System Health on
        [Parameter(Mandatory=$true)]
        [string]$ComponentID,
        [Parameter(Mandatory=$False)]
        [string]$componentUserDetails,
        [Parameter(Mandatory=$false)]
        [switch]$OfflineOnly
    )

    $WhereFilterText = ""
    # Check the component user

    If([string]::IsNullOrEmpty($componentUserDetails) -or $OfflineOnly)
    {
        # Set the filter to offline components from Component ID type
        $WhereFilterText = '$_.IsLoggedOn -eq $false'
        Write-LogMessage -type Info -Msg "Checking SystemHealth Status for all $ComponentID offline users" 
    }
    else {
        # Set the filter to the specific component user name
        $WhereFilterText = '$_.ComponentUserName -eq $componentUserDetails'
        Write-LogMessage -type Info -Msg "Checking SystemHealth Status for User $componentUserDetails" 
    }
    # Handle specific use case of PSM ID
    if($ComponentID -eq "PSM") { $URI = $URL_SystemHealthComponent+"SessionManagement" }
    else { $URI = $URL_SystemHealthComponent+$ComponentID }
    $WhereFilter = [scriptblock]::Create($WhereFilterText)
    Try{
        $GetSystemHealthResponse = Invoke-RestMethod -Method Get -Uri $URI -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 4500
        $offlineComponents = @()
        if($null -ne $GetSystemHealthResponse){
            foreach ($Component in ($GetSystemHealthResponse.ComponentsDetails | Where-Object $WhereFilter)){
                if($OfflineOnly){
                    $offlineComponents += $Component
                }
                elseif ($Component.ComponentUserName -eq $componentUserDetails){
                    if ($Component.IsLoggedOn -eq $true){
                        Write-LogMessage -Type "Success" -Msg "$ComponentID = $componentUserDetails Is : Online!"
                    } Else {
                        Write-LogMessage -Type "Warning" -Msg "$ComponentID = $componentUserDetails Is : Offline! <---"
                    }
                }
            }
        }

        if($OfflineOnly){
            # Return all the offline components for further investigation
            return $offlineComponents
        }
    } Catch{
        Throw $(New-Object System.Exception ("Cannot get '$componentUserDetails' status. Error: $($_.Exception.Response.StatusDescription)",$_.Exception))
    }
}
    
#endregion

#region PVWA REST Functions
Function Get-LogonHeader{
    <#
    .SYNOPSIS
        Get-LogonHeader
    .DESCRIPTION
        Get-LogonHeader
    .PARAMETER Credentials
        The REST API Credentials to authenticate
    #>
        param(
            [Parameter(Mandatory=$true)]
            [PSCredential]$Credentials
        )
    
        # Create the POST Body for the Logon
        # ----------------------------------
        $logonBody = @{ username=$Credentials.username.Replace('\','');password=$Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress
            
        try{
            # Logon
            $logonToken = Invoke-RestMethod -Method Post -Uri $URL_PVWALogon -Body $logonBody -ContentType "application/json" -TimeoutSec 2700
    
            # Clear logon body
            $logonBody = ""
        } catch {
            Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)",$_.Exception))
        }
    
        $logonHeader = $null
        If ([string]::IsNullOrEmpty($logonToken))
        {
            Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
        }
    
        # Create a Logon Token Header (This will be used through out all the script)
        # ---------------------------
        If($logonToken.PSObject.Properties.Name -contains "CyberArkLogonResult")
        {
            $logonHeader = @{Authorization = $($logonToken.CyberArkLogonResult)}
        } else {
            $logonHeader = @{Authorization = $logonToken}
        }
        return $logonHeader
}
    
Function Invoke-Logon{ 
    # Get Credentials to Login
    # ------------------------
    $caption = "Enter Credentials"
    $msg = "Enter your Privilege Cloud Admin Account"; 
    $global:creds = $Host.UI.PromptForCredential($caption,$msg,"","")
    try{
        # Ignore SSL Cert issues
        IgnoreCert
        # Login to PVWA
        $script:pvwaLogonHeader = Get-LogonHeader -Credentials $creds
    } catch {
        Throw $(New-Object System.Exception ("Error logging on to PVWA",$_.Exception))
    }
    # Clear Stored Credentials
    #$creds = $null
}

Function Invoke-Logoff{
    try{
        Write-LogMessage -type Info -Msg "Logoff Session..."
        Invoke-RestMethod -Method Post -Uri $URL_PVWALogoff -Headers $pvwaLogonHeader -ContentType "application/json" | Out-Null
    } catch {
        Throw $(New-Object System.Exception ("Error logging off from PVWA",$_.Exception))
    }
}
    
#endregion

#region Helper functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-CurrentUserLocalAdmin
# Description....: Check if the current user is a Local Admin
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function Test-CurrentUserLocalAdmin
{
<#
.SYNOPSIS
	Method to check a service login options and verify that the running user has 'Login as service' rights
.DESCRIPTION
	Check if a service is running with a local user and check if the user has the required user rights to run as service
.PARAMETER ServiceName
	The Service Name to Check Login info for
.PARAMETER UserName
	The User Name to Check 'Login as a Service' for
#>
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.SecurityIdentifier] "S-1-5-32-544")  # Local Administrators group SID
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-RandomPassword
# Description....: Creates a new random password
# Parameters.....: Length, (Switch)Lowercase, (Switch)Uppercase, (Switch)Numbers, (Switch)Symbols
# Return Values..: A random password based on the requirements
# =================================================================================================================================
Function New-RandomPassword{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Length, Type uint32, Length of the random string to create.
        [Parameter(Mandatory=$true, Position=0)]
        [ValidatePattern('[0-9]+')]
        [ValidateRange(1,100)]
        [uint32]$Length,

        # Lowercase, Type switch, Use lowercase characters.
        [Parameter(Mandatory=$false)]
        [switch]$Lowercase=$false,
        
        # Uppercase, Type switch, Use uppercase characters.
        [Parameter(Mandatory=$false)]
        [switch]$Uppercase=$false,

        # Numbers, Type switch, Use alphanumeric characters.
        [Parameter(Mandatory=$false)]
        [switch]$Numbers=$false,

        # Symbols, Type switch, Use symbol characters.
        [Parameter(Mandatory=$false)]
        [switch]$Symbols=$false
    )
    Begin
    {
        if (-not($Lowercase -or $Uppercase -or $Numbers -or $Symbols)) 
        {
            throw "You must specify one of: -Lowercase -Uppercase -Numbers -Symbols"
        }

        # Specifies bitmap values for character sets selected.
        $CHARSET_LOWER=1
        $CHARSET_UPPER=2
        $CHARSET_NUMBER=4
        $CHARSET_SYMBOL=8

        # Creates character arrays for the different character classes, based on ASCII character values.
        $charsLower=97..122 | ForEach-Object{ [Char] $_ }
        $charsUpper=65..90 | ForEach-Object{ [Char] $_ }
        $charsNumber=48..57 | ForEach-Object{ [Char] $_ }
        $charsSymbol=35,36,40,41,42,44,45,46,58,59,63,64,95 | ForEach-Object{ [Char] $_ }
    }
    Process
    {
        # Contains the array of characters to use.
        $charList=@()
        # Contains bitmap of the character sets selected.
        $charSets=0
        if ($Lowercase) 
        {
            $charList+=$charsLower
            $charSets=$charSets -bor $CHARSET_LOWER
        }
        if ($Uppercase) 
        {
            $charList+=$charsUpper
            $charSets=$charSets -bor $CHARSET_UPPER
        }
        if ($Numbers) 
        {
            $charList+=$charsNumber
            $charSets=$charSets -bor $CHARSET_NUMBER
        }
        if ($Symbols) 
        {
            $charList+=$charsSymbol
            $charSets=$charSets -bor $CHARSET_SYMBOL
        }

        <#
        .SYNOPSIS
            Test string for existence specified character.
        .DESCRIPTION
            examine each character of a string to determine if it contains a specified characters
        .EXAMPLE
            Test-StringContents in string
        #>
        function Test-StringContents([String] $test, [Char[]] $chars) 
        {
            foreach ($char in $test.ToCharArray()) 
            {
                if ($chars -ccontains $char) 
                {
                    return $true 
                }
            }
            return $false
        }

        do 
        {
            # No character classes matched yet.
            $flags=0
            $output=""
            # Create output string containing random characters.
            1..$Length | ForEach-Object { $output+=$charList[(get-random -maximum $charList.Length)] }

            # Check if character classes match.
            if ($Lowercase) 
            {
                if (Test-StringContents $output $charsLower) 
                {
                    $flags=$flags -bor $CHARSET_LOWER
                }
            }
            if ($Uppercase) 
            {
                if (Test-StringContents $output $charsUpper) 
                {
                    $flags=$flags -bor $CHARSET_UPPER
                }
            }
            if ($Numbers) 
            {
                if (Test-StringContents $output $charsNumber) 
                {
                    $flags=$flags -bor $CHARSET_NUMBER
                }
            }
            if ($Symbols) 
            {
                if (Test-StringContents $output $charsSymbol) 
                {
                    $flags=$flags -bor $CHARSET_SYMBOL
                }
            }
        }
        until ($flags -eq $charSets)
    }
    End
    {   
    	$output
    }
}

Function Stop-CYBRService
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ServiceName
    )
    try{
        #Check If need to Stop CPM or PSM
        $CAStopped = "Stopped"
        $CAStopping = "StopPending"
        $CAStop = "Stop"
        Write-LogMessage -type Info -Msg "Stopping '$ServiceName' Service..."
        #get process ID
        $Service = (Get-WmiObject win32_service | where {$_.name -eq $ServiceName} -ErrorAction SilentlyContinue).ProcessID
        #kill the process
        Stop-Process $Service -Force | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
        #stop service, this makes sure the next status command receives a proper status as kill command is very abrupt.
        Get-Service $ServiceName | Stop-Service -Force -ErrorAction SilentlyContinue
        $ServiceStatus = Get-Service -Name $ServiceName | Select-Object -ExpandProperty status
        if($ServiceStatus -eq $CAStopped){
            Write-LogMessage -type success -Msg "Successfully $CAStopped Service: $($service.name)."
        }
        Else{
            Write-LogMessage -type Warning -Msg "Couldn't $CAStop Service: $($service.name) Do it Manually."
        }
    } catch {
        Throw $(New-Object System.Exception ("Error stopping the service '$ServiceName'.",$_.Exception))
    }
}
Function Start-CYBRService
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $ServiceName
    )
    try{
        #Check If need to Stop CPM or PSM
        $CAStarted = "Started"
        $CAStart = "Start"
        $CARunning = "Running"
        $Service = Get-Service $ServiceName
        $service.Start()
        $Service.WaitForStatus($CARunning,'00:00:20')
        $service.refresh()
        $ServiceStatus = Get-Service -Name $Service.Name | Select-Object -ExpandProperty status
        if($ServiceStatus -eq $CARunning){
            Write-LogMessage -type success -Msg "Successfully $CAStarted Service: $($service.name)."
        }
        Else{
            Write-LogMessage -type Warning -Msg "Couldn't $CAStart Service: $($service.name) Do it Manually."
        }
    } catch {
        Throw $(New-Object System.Exception ("Error starting the service '$ServiceName'. Check Service Status and start it Manually."))
    }
}

Function IgnoreCert{
#Ignore certificate error
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
		$certCallback = @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;
			public class ServerCertificateValidationCallback
			{
				public static void Ignore()
				{
					if(ServicePointManager.ServerCertificateValidationCallback ==null)
					{
						ServicePointManager.ServerCertificateValidationCallback += 
							delegate
							(
								Object obj, 
								X509Certificate certificate, 
								X509Chain chain, 
								SslPolicyErrors errors
							)
							{
								return true;
							};
					}
				}
			}
"@
			Add-Type $certCallback
	}
	[ServerCertificateValidationCallback]::Ignore()
}

Function Show-Menu
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$Items
    )
    # Write the menu
    #Clear-Host
    Write-Host "================ ResetCredFile Guide ================"
    Write-Host ""
    Write-Host "Displaying Only Detected CyberArk Services:"
    Write-Host "Please select an option:"
    Write-Host ""
    $i = 1
    $keys = @("Q")
    Write-LogMessage -type debug -Msg "Going over $($Items.Count) items..."
    foreach($item in $Items)
    {
        Write-Host "$($i). $item"
        $keys += $i
        $i++
    }
    
    Write-Host "Q. Press Q to Quit"

    # Read the answer
    $answer = Read-Host "`nSelect"
    if ($answer -notin $keys)
    {
        Throw "Invalid Option...Exiting..."
    }
    return $answer.ToString()
}

Function Get-CredFileUser
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$File
    )
    try{
        $fileUserName = ((Get-Content $File | Select-Object -Index 2).split("=")[1]).Trim()
        return $fileUserName
    } catch {
        Write-LogMessage -type Error -MSG "Could not find CredFile user name from file '$file'"
        return $null
    }
}

Function Test-SystemLogs
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComponentID,
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ })]
        [string]$LogPath
    )
    $retResult = $true
    # Need to wait a few seconds because CPM logs are cleared twice after restart
    Start-Sleep -Seconds 5
    # Check the log is not empty
    if(![string]::IsNullOrEmpty($(Get-Content -Path $LogPath)))
    {
        Write-LogMessage -type Error -Msg "$ComponentID Log '$LogPath' has some errors, please check it."
        $retResult = $False
    }
    Else
    {
        $retResult = $True
    }

    return $retResult
}

Function Find-UserInSystemLogs
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string[]]$LogPaths
    )
    $retUser = $null
    ForEach($log in $LogPaths)
    {
        If(Test-Path -Path $log)
        {
            If(Get-Content -Path $log | where {$_ -Match $User}){
                $retUser = $Matches[0]
                break
            }
        }
        Else
        {
            Write-LogMessage -type Warning -MSG "Could not find log file: '$log' - skipping"
        }
    }
    
    return $retUser
}
#endregion

#region Functions

Function Invoke-GenerateCredFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComponentID,
        [Parameter(Mandatory=$true)]
        [string]$ComponentVersion,
        [Parameter(Mandatory=$true)]
        [string]$ComponentPath,
        [Parameter(Mandatory=$true)]
        [string]$FileName,
        [Parameter(Mandatory=$true)]
        [string]$ComponentUser,
        [Parameter(Mandatory=$true)]
        [securestring]$NewPassword
    )
    try{
        #Generate a new password with Complexity and we use it later for the Vault part
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword) #Convert Password to BSTR
        $GetComponentUserDetailsNewPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Convert Password to Plaintext
        Write-LogMessage -type Info -MSG "Generating CredFile: '$FileName'"
        #Generate Cred, Check if component is version 12 or lower and select the relevant cred file command
        If($ComponentVersion -gt 12)
        {
            # Set the AppType and ExePath parameters based on the Component ID
            If($ComponentID -eq "CPM")
            {
                # Run the CreateCredFile command
                & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /AppType "CPM" /DPAPIMachineProtection /EntropyFile /Hostname /IpAddress
            }
            ElseIf($ComponentID -eq "PSM")
            {
                # Run the CreateCredFile command
                & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /AppType "PSMApp" /DPAPIMachineProtection /EntropyFile /ExePath $(Join-Path -Path $ComponentPath -ChildPath "CAPSM.exe") /Hostname /IpAddress
            }
        } Else {
            $appType = $ComponentID
            If($ComponentID -eq "PSM") { $appType = "PSMApp" }
            & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /AppType $appType
        }
    } catch {
        Throw $(New-Object System.Exception ("Error generating CredFile for file '$FileName'.",$_.Exception))
    }
}

Function Invoke-ResetCredFile
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSObject]
        $Component
    )
    try{
        $generatedPassword = New-RandomPassword -Length 20 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force
        $Component.InitPVWAURL()
        # Prompt User and get Token
        Invoke-Logon
        # For cases where there is more than one service to stop
        Foreach($svc in $Component.ServiceName)
        {
            Stop-CYBRService -ServiceName $svc
        }
        
        # Set all parameters for the Generate Cred File function
        $generateCredFileParameters = @{
            ComponentID = $Component.Name;
            ComponentVersion = $Component.Version;
            ComponentPath = $Component.Path;        
            NewPassword = $generatedPassword
        }
        #Run through each existing cred File (For CPM: User.ini, for PSM: psmapp.cred, psmgw.cred) and generate cred using $ComponentUser
        Foreach($credFile in $Component.ComponentUser)
        {
            #Pull the User from the cred file
            $ComponentUser = $(Get-CredFileUser -File $credFile)
            if([string]::IsNullOrEmpty($ComponentUser))
            {
                # In case we did not find the Component User from the credFile - Look in other places
                Write-LogMessage -Type Info -MSG "Could not find Component User from CredFile, trying to look for all offline components"
                # Look for all offline components
                $offlineComponents = $(Get-SystemHealth -ComponentID $Component.Name -OfflineOnly)
                # Compare offline components to the specific component logs
                Foreach($user in $offlineComponents)
                {
                    $foundUser = $(Find-UserInSystemLogs -User $User.ComponentUserName -LogPaths $Component.ServiceLogs)
                    If(! [string]::IsNullOrEmpty($foundUser)){
                        Write-LogMessage -Type Info -MSG "Found a match between an offline component user '$foundUser' and local logs, will use it to generate CredFile."
                        $ComponentUser = $foundUser
                        #If the $CredFile is psmgw.cred then we split the SystemHealth PSM App user into 2 strings and replace "PSMApp_blabla" with "PSMgw_blabla" so we also reset the gw cred.
                            If ($credFile -like "*psmgw.cred*"){
                            $ComponentUser = "PSMGw_"+$foundUser.split("_")[1]
                            }
                        Break
                    }
                }
                If($offlineComponents.Count -eq 0 -or $ComponentUser -eq $null)
                {
                    # We couldn't find any component User - ask the user to input the user name
                    Write-LogMessage -Type Info -MSG "Couldn't match offline component user in SystemHealth in local Logs, will have to input manually."
                    $ComponentUser = $(Read-Host "Enter the relevant user name for CredFile: '$credFile'")
                }
            }
            Invoke-GenerateCredFile @generateCredFileParameters -FileName $credFile -ComponentUser $ComponentUser
            # Reset User pw in the vault and activate it
            Get-UserAndResetPassword -ComponentUser $ComponentUser -NewPassword $generatedPassword
            #extract CPM component name to script score so we can use it for apikey reset.
            if($typeChosen = "CPM"){
            $global:apiKeyUsername = $ComponentUser
            $global:apiKeyPath = $Component.Path
            }
        }
        # For cases where there is more than one service to start
        Foreach($svc in $Component.ServiceName)
        {
            Start-CYBRService -ServiceName $svc
        }
        Get-SystemHealth -componentUserDetails $(Get-CredFileUser -File $Component.ComponentUser[0]) -ComponentID $Component.Name
        Test-SystemLogs -ComponentID $Component.Name -LogPath $Component.serviceLogs[0] | Out-Null
        Invoke-Logoff
    } catch {
        Throw $(New-Object System.Exception ("Error in the flow of Resetting component $($Component.Name) credentials file.",$_.Exception))
    }
}

Function Get-UserAndResetPassword{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComponentUser,
        [Parameter(Mandatory=$true)]
        [SecureString]$NewPassword
    )
    try{
        $SearchComponentUserURL = $URL_Users+"?filter=componentUser&search=$ComponentUser"
        $GetUsersResponse = Invoke-RestMethod -Method Get -Uri $SearchComponentUserURL -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700
        If($null -ne $GetUsersResponse){
            #Try to reset Password
            Try{
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword) #Convert Password to BSTR
                $GetComponentUserDetailsNewPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Convert Password to Plaintext
                $BodyResetPW = @{ id = ""+$GetUsersResponse.Users.id+"" ; newPassword = $GetComponentUserDetailsNewPW } | ConvertTo-Json -Compress #Prep Body for API call
                Write-LogMessage -Type Info -Msg "Resetting Password for User: $ComponentUser"
                $SetNewPassword = Invoke-RestMethod -Method POST -Uri ($URL_UserResetPassword -f $GetUsersResponse.Users.id) -Headers $pvwaLogonHeader -ContentType "application/json" -Body $BodyResetPW -TimeoutSec 2700 #Reset Pass
                Write-LogMessage -Type Info -Msg "Activating User: $ComponentUser" 
                $ActivateUser = Invoke-RestMethod -Method POST -Uri ($URL_UserActivate -f $GetUsersResponse.Users.id) -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700 #activate user
                Write-LogMessage -Type Success -Msg "Successfully reset Password in the Vault for User: $ComponentUser" 
            }
            Catch
            {
                Write-LogMessage -Type Error -Msg "There was an error Restting or Activating user '$ComponentUser'. The error was: $($_.Exception.Response.StatusDescription)"
                Throw $(New-Object System.Exception ("There was an error Restting or Activating user '$ComponentUser'.",$_.Exception))
            }
        }
    } catch {
        Write-LogMessage -Type Error -Msg "There was an error finding user '$ComponentUser'. The error was: $($_.Exception.Response.StatusDescription)"
        Throw $(New-Object System.Exception ("There was an error finding user '$ComponentUser'.",$_.Exception))
    }
}

Function Invoke-ResetAPIKey
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$pathApikey,
        [Parameter(Mandatory=$true)]
        [string]$apiUser,
        [Parameter(Mandatory=$true)]
        [string]$AdminUser
    )

Add-Type -AssemblyName System.Windows.Forms
$wshell = New-Object -ComObject wscript.shell
$ApiLogs = "$pathApiKey`Vault\Logs\ApiKeyManager.log"

#Purge logs before execution
Remove-Item $ApiLogs -Force -ErrorAction SilentlyContinue

 Write-LogMessage -type Info -MSG "Resetting CPM Scanner ApiKey, this can take a few secs..."
$wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
[System.Windows.Forms.SendKeys]::SendWait(($creds.GetNetworkCredential().password))
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
& "$pathApikey\Vault\ApiKeyManager.exe" revoke -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
Start-Sleep 1
$wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
[System.Windows.Forms.SendKeys]::SendWait(($creds.GetNetworkCredential().password))
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
& "$pathApikey\Vault\ApiKeyManager.exe" add -f "$pathApikey`Vault\apikey.ini" -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"

if(gc $ApiLogs | Select-String "ERROR"){
Write-LogMessage -type Warning -MSG "Couldn't reset API key, check for errors in logfile: $ApiLogs"
}

$creds = $null
}

# -----------------------------------
# Script Begins Here
Write-LogMessage -type Info -MSG "Starting Create CredFile helper script" -Header
# Check latest version
$gitHubLatestVersionParameters = @{
    currentVersion = $ScriptVersion;
    repositoryName = "pCloudServices/CreateCredHelper";
    scriptVersionFileName = "CreateCredFile-Helper.ps1";
    sourceFolderPath = $PSScriptRoot;
    
    # More parameters that can be used
    # repositoryFolderPath = "FolderName";
    # branch = "main";
    # versionPattern = "ScriptVersion";
}

If(! $SkipVersionCheck)
{
	try{
        Write-LogMessage -type Info -Msg "Current script version $ScriptVersion"
        $isLatestVersion = $(Test-GitHubLatestVersion @gitHubLatestVersionParameters)
		If($isLatestVersion -eq $false)
		{
            # Skip the version check so we don't get into a loop
			$scriptPathAndArgs = "`& `"$PSScriptRoot\CreateCredFile-Helper.ps1`" -SkipVersionCheck"
			Write-LogMessage -type Info -Msg "Finished Updating, relaunching the script"
			# Run the updated script
			Invoke-Expression $scriptPathAndArgs
			# Exit the current script
			return
		}
	} catch {
		Write-LogMessage -type Error -Msg "Error checking for latest version. Error: $(Join-ExceptionMessage $_.Exception)"  
	}
}

If ($(Test-CurrentUserLocalAdmin) -eq $False)
{
	Write-LogMessage -Type Error -Msg "You must be logged on as a local administrator in order to run this script"
    pause
	return
}

try{
    #Create A Dynamic Menu based on the services found
    $detectedComponents = $(Find-Components)
    If(($null -ne $detectedComponents) -and ($detectedComponents.Name.Count -gt 0))
    {
        # DEBUG
        #$detectedComponents.DisplayName
        # Show the menu
        $answer = Show-Menu -Items $detectedComponents.DisplayName
        # Check the user chosen answer
        If ($answer -eq "Q")
        {
            Write-Host "Exiting..." -ForegroundColor Gray
            break
        }
        Else
        {
            $answer = [int]$answer #if answer is not a letter (Q) convert to int so we can use the below command
            $typeChosen = $detectedComponents[$answer-1]
            Invoke-ResetCredFile -Component $typeChosen
            if($typeChosen.Name -eq "CPM"){
            Invoke-ResetAPIKey -pathApikey $apiKeyPath -apiUser $apiKeyUsername -AdminUser $creds.UserName
            }
            #Maybe in the future add AIM Here (ComponentID=AIM)
        }
    }
    else {
        Write-LogMessage -Type Warning -MSG "There were no CyberArk components found on this machine"
    }
} catch {
    Write-LogMessage -type Error -Msg "There was an error running the script. Error $(Join-ExceptionMessage $_.Exception)"
}
# Script ended
Write-LogMessage -type Info -MSG "Create CredFile helper script ended" -Footer
return
# SIG # Begin signature block
# MIIfdQYJKoZIhvcNAQcCoIIfZjCCH2ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcrK0JrSD7Zn8w
# JUZioohYk2oxkSiytDLe+ya013JAUKCCDnUwggROMIIDNqADAgECAg0B7l8Wnf+X
# NStkZdZqMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
# bG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9i
# YWxTaWduIFJvb3QgQ0EwHhcNMTgwOTE5MDAwMDAwWhcNMjgwMTI4MTIwMDAwWjBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRf
# JMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpi
# Lx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR
# 5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hp
# sk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Sa
# er9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaOCASIwggEeMA4GA1Ud
# DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSP8Et/qC5FJK5N
# UPpjmove4t0bvDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzA9Bggr
# BgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL3Jvb3RyMTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL3Jvb3QuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
# FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG
# 9w0BAQsFAAOCAQEAI3Dpz+K+9VmulEJvxEMzqs0/OrlkF/JiBktI8UCIBheh/qvR
# XzzGM/Lzjt0fHT7MGmCZggusx/x+mocqpX0PplfurDtqhdbevUBj+K2myIiwEvz2
# Qd8PCZceOOpTn74F9D7q059QEna+CYvCC0h9Hi5R9o1T06sfQBuKju19+095VnBf
# DNOOG7OncA03K5eVq9rgEmscQM7Fx37twmJY7HftcyLCivWGQ4it6hNu/dj+Qi+5
# fV6tGO+UkMo9J6smlJl1x8vTe/fKTNOvUSGSW4R9K58VP3TLUeiegw4WbxvnRs4j
# vfnkoovSOWuqeRyRLOJhJC2OKkhwkMQexejgcDCCBKcwggOPoAMCAQICDkgbagep
# Qkweqv7zzfEPMA0GCSqGSIb3DQEBCwUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTE2MDYxNTAwMDAwMFoXDTI0MDYxNTAwMDAwMFowbjELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExRDBCBgNVBAMTO0dsb2Jh
# bFNpZ24gRXh0ZW5kZWQgVmFsaWRhdGlvbiBDb2RlU2lnbmluZyBDQSAtIFNIQTI1
# NiAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2be6Ja2U81u+
# QQYcU8oMEIxRQVkzeWT0V53k1SXE7FCEWJhyeUDiL3jUkuomDp6ulXz7xP1xRN2M
# X7cji1679PxLyyM9w3YD9dGMRbxxdR2L0omJvuNRPcbIirIxNQduufW6ag30EJ+u
# 1WJJKHvsV7qrMnyxfdKiVgY27rDv0Gqu6qsf1g2ffJb7rXCZLV2V8IDQeUbsVTrM
# 0zj7BAeoB3WCguDQfne4j+vSKPyubRRoQX92Q9dIumBE4bdy6NDwIAN72tq0BnXH
# sgPe+JTGaI9ee56bnTbgztJrxsZr6RQitXF+to9aH9vnbvRCEJBo5itFEE9zuizX
# xTFqct1jcwIDAQABo4IBYzCCAV8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQG
# CCsGAQUFBwMDBggrBgEFBQcDCTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
# BBTcLFgsKm81LZ95lahIXcRtPlO/uTAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpj
# move4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3Nw
# Mi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDov
# L2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBiBgNVHSAEWzBZMAsGCSsG
# AQQBoDIBAjAHBgVngQwBAzBBBgkrBgEEAaAyAV8wNDAyBggrBgEFBQcCARYmaHR0
# cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEL
# BQADggEBAHYJxMwv2e8eS6n4V/NAOSHKTDwdnikrINQrRNKIzhoNBc+Dgbvrabwx
# jSrEx0TMYGCUHM+h4QIkDq1bvizCJx5nt+goHzJR4znzmN+4ny6LKrR7CgO8vTYE
# j8nQnE+jAieZsPBF6TTf5DqjtwY32G8qeZDU1E5YcexTqWGY9zlp4BKcV1hyhicp
# pR3lMvMrmZdavyuwPLQG6g5k7LfNZYAkF8LZN/WxJhA1R3uaArpUokWT/3m/GozF
# n7Wf33jna1DxR5RpSyS42gXoDJ1PBuxKMSB+T12GhC81o82cwYRXHx+twOKkse8p
# ayGXptT+7QM3sPz1jSq83ISD497D518wggV0MIIEXKADAgECAgxUZhOjzncM/KH3
# 8lwwDQYJKoZIhvcNAQELBQAwbjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExRDBCBgNVBAMTO0dsb2JhbFNpZ24gRXh0ZW5kZWQgVmFsaWRh
# dGlvbiBDb2RlU2lnbmluZyBDQSAtIFNIQTI1NiAtIEczMB4XDTE5MDQwMjE0MDg0
# OVoXDTIyMDQwMjE0MDg0OVowgcgxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0
# aW9uMRIwEAYDVQQFEwk1MTIyOTE2NDIxEzARBgsrBgEEAYI3PAIBAxMCSUwxCzAJ
# BgNVBAYTAklMMRkwFwYDVQQIExBDZW50cmFsIERpc3RyaWN0MRQwEgYDVQQHEwtQ
# ZXRhaCBUaWt2YTEfMB0GA1UEChMWQ3liZXJBcmsgU29mdHdhcmUgTHRkLjEfMB0G
# A1UEAxMWQ3liZXJBcmsgU29mdHdhcmUgTHRkLjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAJV4PSof8jnpCLHF1yZJ+XvtWnYGKGw/tnCz08EdWiwJdn5P
# BB/VGpv5HHsoDk4tefQh17oH0SstHC0Oc1oifj27y01rStEMY0EP1HwU10bRrpzR
# 5WN3G8sZtvy4KfJATy7+dNF6IcrSuE25niWEclMhABzktX0pZuFaiHPaj0SVrakv
# l2UXCHL1l5LZpyybJ3uI+C4Lw8BD9pL+G6EjXaLde5EzwRVsXsZcqZTJvodRLY+E
# LV3rrdO8WVrfLKOVFsturID1UtIMdKZuwm5MyoIQnr2ehvam9KaEMWYCZPsubCuh
# fQ5tuPbcmFLYNgpc8bp8xkd+rL0ufFpZNryvUgMCAwEAAaOCAbUwggGxMA4GA1Ud
# DwEB/wQEAwIHgDCBoAYIKwYBBQUHAQEEgZMwgZAwTgYIKwYBBQUHMAKGQmh0dHA6
# Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZXh0ZW5kY29kZXNpZ25z
# aGEyZzNvY3NwLmNydDA+BggrBgEFBQcwAYYyaHR0cDovL29jc3AyLmdsb2JhbHNp
# Z24uY29tL2dzZXh0ZW5kY29kZXNpZ25zaGEyZzMwVQYDVR0gBE4wTDBBBgkrBgEE
# AaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20v
# cmVwb3NpdG9yeS8wBwYFZ4EMAQMwCQYDVR0TBAIwADBFBgNVHR8EPjA8MDqgOKA2
# hjRodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZXh0ZW5kY29kZXNpZ25zaGEy
# ZzMuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS7YyxK68gq0o5p
# okp1Am8I0WS8UzAfBgNVHSMEGDAWgBTcLFgsKm81LZ95lahIXcRtPlO/uTANBgkq
# hkiG9w0BAQsFAAOCAQEAlUBQ5rapeQLAThCcNFYPAuUPUh0Q9GAghhdcQQWmod1z
# a/wS0ZRZHCYEfWTXLl57ltT9PIP3vMS5pf5U+Zy7eVTdv47L8HLHw7IC0XgA2yHn
# 33PyMrIzdbfkkskqLxrlnYJg4UMD6/5X5eWIn3+m8ZO3VAedNBpNfaooVo6drFel
# P6M4qq3Nu3/RUI9+qNJhNT39NPFmFxeqNnT92bOiBadm+q1YZ8XMgvjQFEfVt6Or
# n1wxxinsJ2mDG4qmfMaGWY6kFiUNhy7ES8JRgeiq7SRW5SHzSGU+0i6LPcPQJC6Y
# aP/c0vMglM0C7/z959T1Oerqs1MWMBJaismNYTzFZTGCEFYwghBSAgEBMH4wbjEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExRDBCBgNVBAMT
# O0dsb2JhbFNpZ24gRXh0ZW5kZWQgVmFsaWRhdGlvbiBDb2RlU2lnbmluZyBDQSAt
# IFNIQTI1NiAtIEczAgxUZhOjzncM/KH38lwwDQYJYIZIAWUDBAIBBQCgfDAQBgor
# BgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg9VNPjSt7Cgyl
# RdP9nmXsjHECBGfumqVCLdJVE6WJnOEwDQYJKoZIhvcNAQEBBQAEggEAgY6jfZi4
# GojhehrLiKnm54J5tXuqYp2af8tYDA9+jlwhpI/xRD5tY9OUhUglLwYg/JqCEaLE
# asVxOgpfP2zLi7+aKzAigSRaFIC27xtkMyChi/GZC2FpheByTYYO1TzENc9SuV+f
# 8PHeBd+5XPRkd51s7AkKx4zhS9lizmv9WQ7L3YxIttvzQJMhvjDHSPtaCZwHPb/e
# eQKDeE9YYMwWM9ZoXLTqkG2rZzt2hZST3uO/Mrp/j58V8YVceZb0DW4cjtXyj4fi
# Z7fgpW3wreXyOWwfYVsWN9s5LUCenJoJjEh0ycprPkcRBcGPTamYE0tWGaF5Dk6Y
# 36E+BLqavhaCgaGCDiswgg4nBgorBgEEAYI3AwMBMYIOFzCCDhMGCSqGSIb3DQEH
# AqCCDgQwgg4AAgEDMQ0wCwYJYIZIAWUDBAIBMIH+BgsqhkiG9w0BCRABBKCB7gSB
# 6zCB6AIBAQYLYIZIAYb4RQEHFwMwITAJBgUrDgMCGgUABBTqZmcytflYmmy+rkyH
# psEZqqmeOAIUQdItWKNAmF9tkhymgiqpQIqQq6wYDzIwMjExMjMwMTY0NzU1WjAD
# AgEeoIGGpIGDMIGAMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNV
# BAMTKFN5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzOgggqL
# MIIFODCCBCCgAwIBAgIQewWx1EloUUT3yYnSnBmdEjANBgkqhkiG9w0BAQsFADCB
# vTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
# ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJp
# U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQDEy9W
# ZXJpU2lnbiBVbml2ZXJzYWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAe
# Fw0xNjAxMTIwMDAwMDBaFw0zMTAxMTEyMzU5NTlaMHcxCzAJBgNVBAYTAlVTMR0w
# GwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMg
# VHJ1c3QgTmV0d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFt
# cGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtZnVlVT52M
# cl0agaLrVfOwAa08cawyjwVrhponADKXak3JZBRLKbvC2Sm5Luxjs+HPPwtWkPhi
# G37rpgfi3n9ebUA41JEG50F8eRzLy60bv9iVkfPw7mz4rZY5Ln/BJ7h4OcWEpe3t
# r4eOzo3HberSmLU6Hx45ncP0mqj0hOHE0XxxxgYptD/kgw0mw3sIPk35CrczSf/K
# O9T1sptL4YiZGvXA6TMU1t/HgNuR7v68kldyd/TNqMz+CfWTN76ViGrF3PSxS9TO
# 6AmRX7WEeTWKeKwZMo8jwTJBG1kOqT6xzPnWK++32OTVHW0ROpL2k8mc40juu1MO
# 1DaXhnjFoTcCAwEAAaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8E
# CDAGAQH/AgEAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9ycGEwLgYIKwYBBQUHAQEEIjAgMB4GCCsGAQUFBzABhhJo
# dHRwOi8vcy5zeW1jZC5jb20wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3Muc3lt
# Y2IuY29tL3VuaXZlcnNhbC1yb290LmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMzAdBgNVHQ4E
# FgQUr2PWyqNOhXLgp7xB8ymiOH+AdWIwHwYDVR0jBBgwFoAUtnf6aUhHn1MS1cLq
# BzJ2B9GXBxkwDQYJKoZIhvcNAQELBQADggEBAHXqsC3VNBlcMkX+DuHUT6Z4wW/X
# 6t3cT/OhyIGI96ePFeZAKa3mXfSi2VZkhHEwKt0eYRdmIFYGmBmNXXHy+Je8Cf0c
# kUfJ4uiNA/vMkC/WCmxOM+zWtJPITJBjSDlAIcTd1m6JmDy1mJfoqQa3CcmPU1dB
# kC/hHk1O3MoQeGxCbvC2xfhhXFL1TvZrjfdKer7zzf0D19n2A6gP41P3CnXsxnUu
# qmaFBJm3+AZX4cYO9uiv2uybGB+queM6AL/OipTLAduexzi7D1Kr0eOUA2AKTaD+
# J20UMvw/l0Dhv5mJ2+Q5FL3a5NPD6itas5VYVQR9x5rsIwONhSrS/66pYYEwggVL
# MIIEM6ADAgECAhB71OWvuswHP6EBIwQiQU0SMA0GCSqGSIb3DQEBCwUAMHcxCzAJ
# BgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UE
# CxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hB
# MjU2IFRpbWVTdGFtcGluZyBDQTAeFw0xNzEyMjMwMDAwMDBaFw0yOTAzMjIyMzU5
# NTlaMIGAMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRp
# b24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5
# bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzMwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvDoqq+Ny/aXtUF3FHCb2NPIH4dBV3Z5Cc
# /d5OAp5LdvblNj5l1SQgbTD53R2D6T8nSjNObRaK5I1AjSKqvqcLG9IHtjy1GiQo
# +BtyUT3ICYgmCDr5+kMjdUdwDLNfW48IHXJIV2VNrwI8QPf03TI4kz/lLKbzWSPL
# gN4TTfkQyaoKGGxVYVfR8QIsxLWr8mwj0p8NDxlsrYViaf1OhcGKUjGrW9jJdFLj
# V2wiv1V/b8oGqz9KtyJ2ZezsNvKWlYEmLP27mKoBONOvJUCbCVPwKVeFWF7qhUhB
# IYfl3rTTJrJ7QFNYeY5SMQZNlANFxM48A+y3API6IsW0b+XvsIqbAgMBAAGjggHH
# MIIBwzAMBgNVHRMBAf8EAjAAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAj
# BggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIw
# GRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEwQAYDVR0fBDkwNzA1oDOgMYYvaHR0
# cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jcmwwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMHcGCCsGAQUFBwEB
# BGswaTAqBggrBgEFBQcwAYYeaHR0cDovL3RzLW9jc3Aud3Muc3ltYW50ZWMuY29t
# MDsGCCsGAQUFBzAChi9odHRwOi8vdHMtYWlhLndzLnN5bWFudGVjLmNvbS9zaGEy
# NTYtdHNzLWNhLmNlcjAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1w
# LTIwNDgtNjAdBgNVHQ4EFgQUpRMBqZ+FzBtuFh5fOzGqeTYAex0wHwYDVR0jBBgw
# FoAUr2PWyqNOhXLgp7xB8ymiOH+AdWIwDQYJKoZIhvcNAQELBQADggEBAEaer/C4
# ol+imUjPqCdLIc2yuaZycGMv41UpezlGTud+ZQZYi7xXipINCNgQujYk+gp7+zvT
# Yr9KlBXmgtuKVG3/KP5nz3E/5jMJ2aJZEPQeSv5lzN7Ua+NSKXUASiulzMub6KlN
# 97QXWZJBw7c/hub2wH9EPEZcF1rjpDvVaSbVIX3hgGd+Yqy3Ti4VmuWcI69bEepx
# qUH5DXk4qaENz7Sx2j6aescixXTN30cJhsT8kSWyG5bphQjo3ep0YG5gpVZ6DchE
# WNzm+UgUnuW/3gC9d7GYFHIUJN/HESwfAD/DSxTGZxzMHgajkF9cVIs+4zNbgg/F
# t4YCTnGf6WZFP3YxggJaMIICVgIBATCBizB3MQswCQYDVQQGEwJVUzEdMBsGA1UE
# ChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0
# IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0ECEHvU5a+6zAc/oQEjBCJBTRIwCwYJYIZIAWUDBAIBoIGkMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjExMjMwMTY0NzU1WjAv
# BgkqhkiG9w0BCQQxIgQgERgDAoRukXxsA7cH/z3ALn830msHJoea4Tl7XXq3WQ8w
# NwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgxHTOdgB9AjlODaXk3nwUxoD54oIBPP72
# U+9dtx/fYfgwCwYJKoZIhvcNAQEBBIIBAGUjJ/V6CKh7qMAnUE6hdALlwydhnxOZ
# DGuRSqqom9g9A86fGMbOdV5+sqHntqqbd9LpAyktx6LF0+ZH1uIGi2p6Mld3bvFy
# o7yO6Wii3svx8I21E69L9ILtICrgtLo1YrBdpSnUYkFzViKvuIfImrE81Nh1myJH
# eq5kIt67sV8VT12/0yi9VaByrMXfQFJIrrGYoAItJ3RQo0v22+8CGFIBfTgHIzr5
# YjsojzOLMQhnChoQCpjYrsXeJtQJ0NiaEoe6TxYwhTy32VOqv2fVoD8GCeRNIqMr
# ASq5UdlYG2+9YTjDY3D7d9VUNEuo5RW4RxmLuvJwN+JN2Z40IMGeYr4=
# SIG # End signature block
