###########################################################################
#
# NAME: Reset Cred File Helper
#
# AUTHOR:  Mike Brook<mike.brook@cyberark.com>
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
    [Switch]$SkipVersionCheck,
    [switch]$skipTLS
)

$Host.UI.RawUI.WindowTitle = "Privilege Cloud CreateCredFile-Helper"
$Script:LOG_FILE_PATH = "$PSScriptRoot\_CreateCredFile-Helper.log"

# Script Version
$ScriptVersion = "2.8"

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
        {
            Write-LogMessage -type Info -MSG "Test-ScriptLatestVersion: Couldn't match Script Version pattern ($versionPattern)"
        }
    }
    catch
    {
        Write-LogMessage -type Info -MSG ("Test-ScriptLatestVersion: Couldn't download and check for latest version", $_.Exception)
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
		Write-LogMessage -type Info -MSG ("Test-GitHubLatestVersion: Couldn't check for latest version $($_.Exception.Message)")
	}
	
    try{
        # Check if we need to download the gitHub version
        If($shouldDownloadLatestVersion -eq $true)
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

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Choice
# Description....: Prompts user for Selection choice
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function Get-Choice{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]
        $Options,

        [Parameter(Position = 2)]
        $DefaultChoice = -1
    )
    if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1))
    {
        Write-Warning "DefaultChoice needs to be a value between 1 and $($Options.Count) or -1 (for none)"
        exit
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:result = ""
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.BackColor = [Drawing.Color]::White
    $form.TopMost = $True
    $form.Text = $Title
    $form.ControlBox = $False
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    #calculate width required based on longest option text and form title
    $minFormWidth = 300
    $formHeight = 44
    $minButtonWidth = 150
    $buttonHeight = 23
    $buttonY = 12
    $spacing = 10
    $buttonWidth = [Windows.Forms.TextRenderer]::MeasureText((($Options | Sort-Object Length)[-1]), $form.Font).Width + 1
    $buttonWidth = [Math]::Max($minButtonWidth, $buttonWidth)
    $formWidth = [Windows.Forms.TextRenderer]::MeasureText($Title, $form.Font).Width
    $spaceWidth = ($options.Count + 1) * $spacing
    $formWidth = ($formWidth, $minFormWidth, ($buttonWidth * $Options.Count + $spaceWidth) | Measure-Object -Maximum).Maximum
    $form.ClientSize = New-Object System.Drawing.Size($formWidth, $formHeight)
    $index = 0
    #create the buttons dynamically based on the options
    foreach ($option in $Options)
    {
        Set-Variable "button$index" -Value (New-Object System.Windows.Forms.Button)
        $temp = Get-Variable "button$index" -ValueOnly
        $temp.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $temp.UseVisualStyleBackColor = $True
        $temp.Text = $option
        $buttonX = ($index + 1) * $spacing + $index * $buttonWidth
        $temp.Add_Click({ 
                $script:result = $this.Text; 
                $form.Close() 
            })
        $temp.Location = New-Object System.Drawing.Point($buttonX, $buttonY)
        $form.Controls.Add($temp)
        $index++
    }
    $shownString = '$this.Activate();'
    if ($DefaultChoice -ne -1)
    {
        $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()'
    }
    $shownSB = [ScriptBlock]::Create($shownString)
    $form.Add_Shown($shownSB)
    [void]$form.ShowDialog()
    return $result
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
		$REGKEY_PSMSERVICEold = "Cyber-Ark Privileged Session Manager" #12.7-
        $REGKEY_PSMSERVICEnew = "CyberArk Privileged Session Manager" #13.0+
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
                            $userType = "CPM"
                            #Create New Fresh Cred File, it will not overwrite an existing one, this is just incase there was no cred to begin with.
                            New-Item (Join-Path -Path $cpmPath -ChildPath "Vault\user.ini") -ErrorAction SilentlyContinue | Get-Acl | Set-Acl (Join-Path -Path $cpmPath -ChildPath "Vault\Vault.ini")
                            $appFilePath = (Join-Path -Path $cpmPath -ChildPath "Vault\user.ini")
                            if (Test-Path $appFilePath){
                                $ComponentUser = @($appFilePath)
                            }
							$myObject = New-Object PSObject -Property @{Name="CPM";DisplayName="CyberArk Password Manager (CPM)";
                                                                        ServiceName=@($REGKEY_CPMSERVICE,$REGKEY_CPMScannerSERVICE);Path=$cpmPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs;UserType=$userType}
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
						Foreach($psmservice in @($REGKEY_PSMSERVICEold,$REGKEY_PSMSERVICEnew)){
                            if($NULL -ne ($componentPath = $(Get-ServiceInstallPath $psmservice)))
                            {
                                $REGKEY_PSMSERVICE = $psmservice
                            }
						}
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
                            $UserType = "PSM"
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
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs;UserType=$UserType}
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
                            $ConfigPath = (Join-Path -Path $AIMPath -ChildPath "Vault\Vault.ini")
							$fileVersion = Get-FileVersion "$AIMPath\AppProvider.exe"
                            $serviceLogsOldTrace = @(Join-Path -Path $AIMPath -ChildPath "Logs\old\APPTrace.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $serviceLogsOldConsole = @(Join-Path -Path $AIMPath -ChildPath "Logs\old\APPConsole.log.*" | Get-ChildItem -Recurse | Select-Object -Last 10)
                            $ServiceLogsMain = @(Join-Path -Path $AIMPath -ChildPath "Logs\APPTrace.log")
                            $ServiceLogs = $ServiceLogsMain + $serviceLogsOldTrace + $serviceLogsOldConsole
                            $UserType = "AppProvider"
                            #Create New Fresh Cred File, it will not overwrite an existing one, this is just incase there was no cred to begin with.
                            New-Item (Join-Path -Path $AIMPath -ChildPath "Vault\AppProviderUser.cred") -ErrorAction SilentlyContinue | Get-Acl | Set-Acl (Join-Path -Path $AIMPath -ChildPath "Vault\Vault.ini")
                            $appFilePath = (Join-Path -Path $AIMPath -ChildPath "Vault\AppProviderUser.cred")
                            if (Test-Path $appFilePath){
                                $ComponentUser = @($appFilePath)
                            }
                            $myObject = New-Object PSObject -Property @{Name="AIM";DisplayName="CyberArk Application Password Provider (AIM)";
                                                                        ServiceName=$REGKEY_AIMSERVICE;Path=$AIMPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs;UserType=$UserType}
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
        [ValidateSet("PVWA","CPM","PSM","AIM")]
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
                    # if false, URL contains IP and we need to prompt for user input.
                    $foundConfig = ($PVWAurl -NotMatch "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
                }
                else {
                    Write-LogMessage -type Warning -Msg "Error reading the configuration file $($ConfigPath)"
                }
            }
            if ($ComponentID -eq "CPM"){
                try{
                    # In case there is more than one address, get the first one
                    $GetPVWAStringURL = ((Get-Content $ConfigPath | Where-Object {$_ -match "Addresses" }).Split("=")[1]).Split(",")[0]
                } catch {
                    Write-LogMessage -type Error -MSG "There was an error finding PVWA Address from vault.ini configuration file"
                    $GetPVWAStringURL = $null
                }
                If(![string]::IsNullOrEmpty($GetPVWAStringURL)){
                    $PVWAurl = $GetPVWAStringURL
                    $foundConfig = $true
                }
            }
            if ($ComponentID -eq "AIM"){
                try{
                    # In case there is more than one address, get the first one
                    $GetPVWAStringURL = ((Get-Content $ConfigPath | Where-Object {$_ -match "Address" }).Split("=")[1]).Split(",")[0]

                    # if false, URL contains IP and we need to prompt for user input.
                    $foundConfig = ($GetPVWAStringURL -NotMatch "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

                    # In case of AIM there is no PVWA record anywhere, but we can determine if vault address is DNS type and has pcloud pattern and convert it to PVWA from it.
                    if (($foundConfig -eq $true) -and (-not([string]::IsNullOrEmpty($GetPVWAStringURL)))){
                        # URL exists and is DNS type, let's check if its pcloud pattern
                        if (($GetPVWAStringURL -like "vault-*.cyberark.com") -or ($_ -like "*vault-*.cyberark.cloud")){
                            # grab first subdomain and trim vault- from it.
                            $portalSubDomainURL = $GetPVWAStringURL.split(".")[0].TrimStart("vault-")
                        }
                        Else{
                            # set $foundConfig to false in case this is non pcloud tenant so it prompts user to enter PVWA again
                            $foundConfig = $False
                         }
                        # Check if standard or shared services implementation.
                        if($GetPVWAStringURL -like "*.cyberark.com"){
                            # standard
                            $script:PVWAurl = "https://$portalSubDomainURL.privilegecloud.cyberark.com"
                        }
                        Elseif($GetPVWAStringURL -like "*.cyberark.cloud"){
                            # ISPSS
                            $script:PVWAurl = "https://$portalSubDomainURL.privilegecloud.cyberark.cloud"
                        }
                    }
                } catch {
                    Write-LogMessage -type Error -MSG "There was an error finding PVWA Address from vault.ini configuration file"
                    $GetPVWAStringURL = $null
                }
            }
        }
        # We Couldn't find PVWA URL so we prompt the user
        if(($foundConfig -eq $False) -or ([string]::IsNullOrEmpty($PVWAurl)))
        {
            Write-LogMessage -type Info -MSG "Couldn't retrieve portal URL from configuration file, let's type it manually:"
            $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
        }
		
		# Let user confirm this is the correct URL, otherwise, enter manually
        $confirmPVWAUrl = Get-Choice -Title "Is this your Portal URL: $PVWAurl" -Options "Yes", "No, let me type." -DefaultChoice 1
        if($confirmPVWAUrl -eq "No, let me type."){
            $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
        }

        Write-LogMessage -type debug -Msg "The PVWA URL to be used is: '$PVWAurl'"
    } Catch{
        Write-LogMessage -type Error -MSG ("There was an error reading the $ComponentID configuration file '$ConfigPath'",$_.Exception)
        Write-LogMessage -type Info -MSG "Couldn't retrieve portal URL from configuration file, let's type it manually:"
        $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
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
            Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.ErrorDetails.Message)"))
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
        if($Service -eq 0){
            Write-LogMessage -type Info -MSG "Service is already stopped, skipping..."
        }
        Else{
            #kill the process
            Stop-Process $Service -Force | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
            #stop service, this makes sure the next status command receives a proper status as kill command is very abrupt.
            Get-Service $ServiceName | Stop-Service -Force -ErrorAction SilentlyContinue
            $ServiceStatus = Get-Service -Name $ServiceName | Select-Object -ExpandProperty status
            if($ServiceStatus -eq $CAStopped){
                Write-LogMessage -type success -Msg "Successfully $CAStopped Service: $($ServiceName)."
            }
            Else{
                Write-LogMessage -type Warning -Msg "Couldn't $CAStop Service: $($ServiceName) Do it Manually."
            }
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
#Set registry to use TLS12
$GetTLS = [Net.ServicePointManager]::SecurityProtocol -match "tls12"
$GetTLSReg86 = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319').SchUseStrongCrypto -eq 1
$GetTLSReg64 = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319\').SchUseStrongCrypto -eq 1

if(($GetTLS -ne $true) -or ($GetTLSReg86 -ne $true) -or ($GetTLSReg64 -ne $true)){
    Write-LogMessage -type Info -MSG "Detected TLS12 is not enforced, enforcing it via registry"
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force -Verbose
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force -Verbose
    Write-LogMessage -type Info -MSG "Please restart powershell to complete TLS12 settings. If this error keeps repeating, rerun the script with -skipTLS flag"
    Pause
    Stop-Process $PID
}

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
    #ERROR: The request was aborted: Could not create SSL/TLS secure channel.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
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
            elseif ($ComponentID -eq "AIM") {
                & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /DPAPIMachineProtection /EntropyFile /Hostname /IpAddress
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
        $generatedPassword = New-RandomPassword -Length 39 -Lowercase -Uppercase -Numbers -Symbols | ConvertTo-SecureString -AsPlainText -Force
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
            Get-UserAndResetPassword -ComponentUser $ComponentUser -UserType $Component.UserType -NewPassword $generatedPassword
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
        [SecureString]$NewPassword,
        [Parameter(Mandatory=$true)]
        [string]$UserType
    )
    try{
        $SearchComponentUserURL = $URL_Users+"?filter=componentUser&search=$ComponentUser&UserType=$UserType"
        $GetUsersResponse = Invoke-RestMethod -Method Get -Uri $SearchComponentUserURL -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700 | Select-Object -ExpandProperty Users | where {$_.username -eq $ComponentUser}
        If($null -ne $GetUsersResponse){
            #Try to reset Password
            Try{
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword) #Convert Password to BSTR
                $GetComponentUserDetailsNewPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Convert Password to Plaintext
                $BodyResetPW = @{ id = ""+$GetUsersResponse.Users.id+"" ; newPassword = $GetComponentUserDetailsNewPW } | ConvertTo-Json -Compress #Prep Body for API call
                Write-LogMessage -Type Info -Msg "Resetting Password for User: $ComponentUser"
                $SetNewPassword = Invoke-RestMethod -Method POST -Uri ($URL_UserResetPassword -f $GetUsersResponse.id) -Headers $pvwaLogonHeader -ContentType "application/json" -Body $BodyResetPW -TimeoutSec 2700 #Reset Pass
                Write-LogMessage -Type Info -Msg "Activating User: $ComponentUser" 
                $ActivateUser = Invoke-RestMethod -Method POST -Uri ($URL_UserActivate -f $GetUsersResponse.id) -Headers $pvwaLogonHeader -ContentType "application/json" -TimeoutSec 2700 #activate user
                Write-LogMessage -Type Success -Msg "Successfully reset Password in the Vault for User: $ComponentUser" 
            }
            Catch
            {
                Write-LogMessage -Type Error -Msg "There was an error Restting or Activating user '$ComponentUser'. The error was: $($_.ErrorDetails.Message)"
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
Write-LogMessage -type Info -MSG "Testing if SendWait function will work..."
$dummyString = "Test"
$teststring = $null
$specialchars = '!@#$%^&*()'',./\`~[]":?<>+|'.ToCharArray()
[string]$simplePw = ($creds.GetNetworkCredential().password)

#Escape curly brackets from SendWait command
if($simplePw -match "{"){$simplePw = $simplePw.Replace("{","_LEFT_")}
if($simplePw -match "}"){$simplePw = $simplePw.Replace("}","_RIGHT_")}
$simplePw = $simplePw.Replace('_LEFT_',"{{}").Replace('_RIGHT_',"{}}")

#Escape special chars that have other meaning in SendKeys class.
foreach($char in $specialchars){
    if($simplePw -match "\$char")
    {
        $simplepw = $simplePw.Replace("$char","{$char}")
    }
}

#we need to test this command since some endpoint agents are blocking it, if its blocked, user will have to enter admin pw manually.
[System.Windows.Forms.SendKeys]::SendWait($dummyString);
[System.Windows.Forms.SendKeys]::SendWait('{ENTER}');
$wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
$teststring = Read-Host -Prompt "Testing SendWait command: "
#if test string contains value, SendWait works
if($teststring){
    $wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
    [System.Windows.Forms.SendKeys]::SendWait($simplePw)
    [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
    & "$pathApikey\Vault\ApiKeyManager.exe" revoke -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
    Start-Sleep 1
    $wshell.AppActivate('Privilege Cloud CreateCredFile-Helper') | Out-Null
    [System.Windows.Forms.SendKeys]::SendWait($simplePw)
    [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
    & "$pathApikey\Vault\ApiKeyManager.exe" add -f "$pathApikey`Vault\apikey.ini" -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
}
Else{
Write-LogMessage -type Warning -Msg "Error Powershell's SendWait command doesn't work, probably because you have Endpoint agent blocking this action."
Write-LogMessage -type Warning -Msg "You will have to input your administrative account manually (the same account pw you input at the start of the script)."
& "$pathApikey\Vault\ApiKeyManager.exe" revoke -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
& "$pathApikey\Vault\ApiKeyManager.exe" add -f "$pathApikey`Vault\apikey.ini" -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
}

if(gc $ApiLogs | Select-String "ERROR"){
Write-LogMessage -type Warning -MSG "Couldn't reset API key, check for errors in logfile: $ApiLogs"
}

$creds = $null
$simplePw = $null
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
    
    # Ignore SSL Cert issues
    if(-not($skipTLS)){IgnoreCert}

    #Create A Dynamic Menu based on the services found
    $detectedComponents = $(Find-Components)
    If(($null -ne $detectedComponents) -and ($detectedComponents.Name.Count -gt 0))
    {
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
               $decisionAPIKey = Get-Choice -Title "Would you like to also reset CPM Scanner APIKey?" -Options "Yes (Recommended)", "No" -DefaultChoice 1
               if($decisionAPIKey -eq "No")
               {
                     Write-LogMessage -Type info -MSG "Selected not to run CPM Scanner APIKey reset."
               }
               Else{
                    Invoke-ResetAPIKey -pathApikey $apiKeyPath -apiUser $apiKeyUsername -AdminUser $creds.UserName
                   }
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
###########
# SIG # Begin signature block
# MIIqRgYJKoZIhvcNAQcCoIIqNzCCKjMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB8DZ+mCDzWBiQS
# UI4xyqrynhjvp1F0jrB7mid7+Oz0faCCGFcwggROMIIDNqADAgECAg0B7l8Wnf+X
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
# vfnkoovSOWuqeRyRLOJhJC2OKkhwkMQexejgcDCCBaIwggSKoAMCAQICEHgDGEJF
# cIpBz28BuO60qVQwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2ln
# biBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkds
# b2JhbFNpZ24wHhcNMjAwNzI4MDAwMDAwWhcNMjkwMzE4MDAwMDAwWjBTMQswCQYD
# VQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xv
# YmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC2LcUw3Xroq5A9A3KwOkuZFmGy5f+lZx03HOV+7JODqoT1
# o0ObmEWKuGNXXZsAiAQl6fhokkuC2EvJSgPzqH9qj4phJ72hRND99T8iwqNPkY2z
# BbIogpFd+1mIBQuXBsKY+CynMyTuUDpBzPCgsHsdTdKoWDiW6d/5G5G7ixAs0sdD
# HaIJdKGAr3vmMwoMWWuOvPSrWpd7f65V+4TwgP6ETNfiur3EdaFvvWEQdESymAfi
# dKv/aNxsJj7pH+XgBIetMNMMjQN8VbgWcFwkeCAl62dniKu6TjSYa3AR3jjK1L6h
# wJzh3x4CAdg74WdDhLbP/HS3L4Sjv7oJNz1nbLFFXBlhq0GD9awd63cNRkdzzr+9
# lZXtnSuIEP76WOinV+Gzz6ha6QclmxLEnoByPZPcjJTfO0TmJoD80sMD8IwM0kXW
# LuePmJ7mBO5Cbmd+QhZxYucE+WDGZKG2nIEhTivGbWiUhsaZdHNnMXqR8tSMeW58
# prt+Rm9NxYUSK8+aIkQIqIU3zgdhVwYXEiTAxDFzoZg1V0d+EDpF2S2kUZCYqaAH
# N8RlGqocaxZ396eX7D8ZMJlvMfvqQLLn0sT6ydDwUHZ0WfqNbRcyvvjpfgP054d1
# mtRKkSyFAxMCK0KA8olqNs/ITKDOnvjLja0Wp9Pe1ZsYp8aSOvGCY/EuDiRk3wID
# AQABo4IBdzCCAXMwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFB8Av0aACvx4ObeltEPZVlC7zpY7
# MB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHoGCCsGAQUFBwEBBG4w
# bDAtBggrBgEFBQcwAYYhaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vcm9vdHIz
# MDsGCCsGAQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2Vy
# dC9yb290LXIzLmNydDA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2Jh
# bHNpZ24uY29tL3Jvb3QtcjMuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsG
# AQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAN
# BgkqhkiG9w0BAQwFAAOCAQEArPfMFYsweagdCyiIGQnXHH/+hr17WjNuDWcOe2LZ
# 4RhcsL0TXR0jrjlQdjeqRP1fASNZhlZMzK28ZBMUMKQgqOA/6Jxy3H7z2Awjuqgt
# qjz27J+HMQdl9TmnUYJ14fIvl/bR4WWWg2T+oR1R+7Ukm/XSd2m8hSxc+lh30a6n
# sQvi1ne7qbQ0SqlvPfTzDZVd5vl6RbAlFzEu2/cPaOaDH6n35dSdmIzTYUsvwyh+
# et6TDrR9oAptksS0Zj99p1jurPfswwgBqzj8ChypxZeyiMgJAhn2XJoa8U1sMNSz
# BqsAYEgNeKvPF62Sk2Igd3VsvcgytNxN69nfwZCWKb3BfzCCBugwggTQoAMCAQIC
# EHe9DgW3WQu2HUdhUx4/de0wDQYJKoZIhvcNAQELBQAwUzELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24g
# Q29kZSBTaWduaW5nIFJvb3QgUjQ1MB4XDTIwMDcyODAwMDAwMFoXDTMwMDcyODAw
# MDAwMFowXDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MjAwBgNVBAMTKUdsb2JhbFNpZ24gR0NDIFI0NSBFViBDb2RlU2lnbmluZyBDQSAy
# MDIwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyyDvlx65ATJDoFup
# iiP9IF6uOBKLyizU/0HYGlXUGVO3/aMX53o5XMD3zhGj+aXtAfq1upPvr5Pc+OKz
# GUyDsEpEUAR4hBBqpNaWkI6B+HyrL7WjVzPSWHuUDm0PpZEmKrODT3KxintkktDw
# tFVflgsR5Zq1LLIRzyUbfVErmB9Jo1/4E541uAMC2qQTL4VK78QvcA7B1MwzEuy9
# QJXTEcrmzbMFnMhT61LXeExRAZKC3hPzB450uoSAn9KkFQ7or+v3ifbfcfDRvqey
# QTMgdcyx1e0dBxnE6yZ38qttF5NJqbfmw5CcxrjszMl7ml7FxSSTY29+EIthz5hV
# oySiiDby+Z++ky6yBp8mwAwBVhLhsoqfDh7cmIsuz9riiTSmHyagqK54beyhiBU8
# wurut9itYaWvcDaieY7cDXPA8eQsq5TsWAY5NkjWO1roIs50Dq8s8RXa0bSV6KzV
# SW3lr92ba2MgXY5+O7JD2GI6lOXNtJizNxkkEnJzqwSwCdyF5tQiBO9AKh0ubcdp
# 0263AWwN4JenFuYmi4j3A0SGX2JnTLWnN6hV3AM2jG7PbTYm8Q6PsD1xwOEyp4Lk
# tjICMjB8tZPIIf08iOZpY/judcmLwqvvujr96V6/thHxvvA9yjI+bn3eD36blcQS
# h+cauE7uLMHfoWXoJIPJKsL9uVMCAwEAAaOCAa0wggGpMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBQlndD8WQmGY8Xs87ETO1ccA5I2ETAfBgNVHSMEGDAWgBQfAL9GgAr8eDm3
# pbRD2VZQu86WOzCBkwYIKwYBBQUHAQEEgYYwgYMwOQYIKwYBBQUHMAGGLWh0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NTBGBggrBgEF
# BQcwAoY6aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvY29kZXNp
# Z25pbmdyb290cjQ1LmNydDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NS5jcmwwVQYDVR0gBE4wTDBB
# BgkrBgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2ln
# bi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwDQYJKoZIhvcNAQELBQADggIBACV1
# oAnJObq3oTmJLxifq9brHUvolHwNB2ibHJ3vcbYXamsCT7M/hkWHzGWbTONYBgIi
# ZtVhAsVjj9Si8bZeJQt3lunNcUAziCns7vOibbxNtT4GS8lzM8oIFC09TOiwunWm
# dC2kWDpsE0n4pRUKFJaFsWpoNCVCr5ZW9BD6JH3xK3LBFuFr6+apmMc+WvTQGJ39
# dJeGd0YqPSN9KHOKru8rG5q/bFOnFJ48h3HAXo7I+9MqkjPqV01eB17KwRisgS0a
# Ifpuz5dhe99xejrKY/fVMEQ3Mv67Q4XcuvymyjMZK3dt28sF8H5fdS6itr81qjZj
# yc5k2b38vCzzSVYAyBIrxie7N69X78TPHinE9OItziphz1ft9QpA4vUY1h7pkC/K
# 04dfk4pIGhEd5TeFny5mYppegU6VrFVXQ9xTiyV+PGEPigu69T+m1473BFZeIbuf
# 12pxgL+W3nID2NgiK/MnFk846FFADK6S7749ffeAxkw2V4SVp4QVSDAOUicIjY6i
# vSLHGcmmyg6oejbbarphXxEklaTijmjuGalJmV7QtDS91vlAxxCXMVI5NSkRhyTT
# xPupY8t3SNX6Yvwk4AR6TtDkbt7OnjhQJvQhcWXXCSXUyQcAerjH83foxdTiVdDT
# HvZ/UuJJjbkRcgyIRCYzZgFE3+QzDiHeYolIB9r1MIIHbzCCBVegAwIBAgIMcE3E
# /BY6leBdVXwMMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUg
# RVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yMjAyMTUxMzM4MzVaFw0yNTAyMTUx
# MzM4MzVaMIHUMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjESMBAGA1UE
# BRMJNTEyMjkxNjQyMRMwEQYLKwYBBAGCNzwCAQMTAklMMQswCQYDVQQGEwJJTDEQ
# MA4GA1UECBMHQ2VudHJhbDEUMBIGA1UEBxMLUGV0YWggVGlrdmExEzARBgNVBAkT
# CjkgSGFwc2Fnb3QxHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xHzAd
# BgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4wggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDys9frIBUzrj7+oxAS21ansV0C+r1R+DEGtb5HQ225eEqe
# NXTnOYgvrOIBLROU2tCq7nKma5qA5bNgoO0hxYQOboC5Ir5B5mmtbr1zRdhF0h/x
# f/E1RrBcsZ7ksbqeCza4ca1yH2W3YYsxFYgucq+JLqXoXToc4CjD5ogNw0Y66R13
# Km94WuowRs/tgox6SQHpzb/CF0fMNCJbpXQrzZen1dR7Gtt2cWkpZct9DCTONwbX
# GZKIdBSmRIfjDYDMHNyz42J2iifkUQgVcZLZvUJwIDz4+jkODv/++fa2GKte06po
# L5+M/WlQbua+tlAyDeVMdAD8tMvvxHdTPM1vgj11zzK5qVxgrXnmFFTe9knf9S2S
# 0C8M8L97Cha2F5sbvs24pTxgjqXaUyDuMwVnX/9usgIPREaqGY8wr0ysHd6VK4wt
# o7nroiF2uWnOaPgFEMJ8+4fRB/CSt6OyKQYQyjSUSt8dKMvc1qITQ8+gLg1budzp
# aHhVrh7dUUVn3N2ehOwIomqTizXczEFuN0siQJx+ScxLECWg4X2HoiHNY7KVJE4D
# L9Nl8YvmTNCrHNwiF1ctYcdZ1vPgMPerFhzqDUbdnCAU9Z/tVspBTcWwDGCIm+Yo
# 9V458g3iJhNXi2iKVFHwpf8hoDU0ys30SID/9mE3cc41L+zoDGOMclNHb0Y5CQID
# AQABo4IBtjCCAbIwDgYDVR0PAQH/BAQDAgeAMIGfBggrBgEFBQcBAQSBkjCBjzBM
# BggrBgEFBQcwAoZAaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# Z3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNydDA/BggrBgEFBQcwAYYzaHR0cDov
# L29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwMFUG
# A1UdIAROMEwwQQYJKwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3
# Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMAkGA1UdEwQCMAAw
# RwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9nc2dj
# Y3I0NWV2Y29kZXNpZ25jYTIwMjAuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8G
# A1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTRWDsgBgAr
# Xx8j10jVgqJYDQPVsTANBgkqhkiG9w0BAQsFAAOCAgEAU50DXmYXBEgzng8gv8EN
# mr1FT0g75g6UCgBhMkduJNj1mq8DWKxLoS11gomB0/8zJmhbtFmZxjkgNe9cWPvR
# NZa992pb9Bwwwe1KqGJFvgv3Yu1HiVL6FYzZ+m0QKmX0EofbwsFl6Z0pLSOvIESr
# ICa4SgUk0OTDHNBUo+Sy9qm+ZJjA+IEK3M/IdNGjkecsFekr8tQEm7x6kCArPoug
# mOetMgXhTxGjCu1QLQjp/i6P6wpgTSJXf9PPCxMmynsxBKGggs+vX/vl9CNT/s+X
# Z9sz764AUEKwdAdi9qv0ouyUU9fiD5wN204fPm8h3xBhmeEJ25WDNQa8QuZddHUV
# hXugk2eHd5hdzmCbu9I0qVkHyXsuzqHyJwFXbNBuiMOIfQk4P/+mHraq+cynx6/2
# a+G8tdEIjFxpTsJgjSA1W+D0s+LmPX+2zCoFz1cB8dQb1lhXFgKC/KcSacnlO4SH
# oZ6wZE9s0guXjXwwWfgQ9BSrEHnVIyKEhzKq7r7eo6VyjwOzLXLSALQdzH66cNk+
# w3yT6uG543Ydes+QAnZuwQl3tp0/LjbcUpsDttEI5zp1Y4UfU4YA18QbRGPD1F9y
# wjzg6QqlDtFeV2kohxa5pgyV9jOyX4/x0mu74qADxWHsZNVvlRLMUZ4zI4y3KvX8
# vZsjJFVKIsvyCgyXgNMM5Z4xghFFMIIRQQIBATBsMFwxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdD
# QyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMAIMcE3E/BY6leBdVXwMMA0GCWCG
# SAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEILQosIcZpap6T2JjXtrfheXZrwCiQ/EHSAuG+RAjtASKMA0GCSqGSIb3
# DQEBAQUABIICAFmJgUBdqNPjOR8yVNN/GYZtZla9kcohSGdJe7FFPq2AFv/rbZuV
# pUFGXgOC/beusMqgXKJikIldA/Bff5kFqFlolnFiP8iEdFYVdIJonp8woqzPI0sC
# T6zFTOzhE/FPoN9PqeYXzBEa95rdHuHWVxBGThz5a+ve/S0JeUFF+1vlewW50dCX
# t9JiLUyYRCaFuKxVl3k7cbpFHWEZ3ksMmvOTcFbFshB03/UyqbLy9RmcB/ofW26E
# 8lpS3JAvO7dnaJB0Y6baQXAHDx3V+L5SS8t+NIBuG3jTDqStOo/0cCS6fJRW9cON
# yK68WkQCwnNbUSupGhd/MfQ2bSnZQbddh28x9k2EEcGmW2bJSTD7MgVHUn08dI18
# q8ljP+XSPN/oAK8oJfn+cUOEUAh3pZUB/gm01dyKKQvMyYpy+XISUHVv8+mseNOu
# 8D6sHIqwZ+EBfRThk+sY+eSd69YUODLpooyvlNjybEz0UktvnJzu2qLA1MdBJqpz
# //0RcGqfMBj18mvItLXw2S+OXKFh2KgCH6srDhpdhMUv4pgkG6Aa3w7Jc1blp/Z5
# ONUnCpa58It7f6juYTuQDpsgdw0UZBGN2qnZj0HMNaSWq4+W84TTGcL9nMn/f577
# 38slVA0imgBj9V5Zhd0+Ix6qhSDZHvMAUu+ZMDFvOoxt3jqQfbE87BFvoYIOLDCC
# DigGCisGAQQBgjcDAwExgg4YMIIOFAYJKoZIhvcNAQcCoIIOBTCCDgECAQMxDTAL
# BglghkgBZQMEAgEwgf8GCyqGSIb3DQEJEAEEoIHvBIHsMIHpAgEBBgtghkgBhvhF
# AQcXAzAhMAkGBSsOAwIaBQAEFE32NUGcTEslUE1nM4Gj4iaogjMVAhUAteJogjGD
# ruQPWMH4iNWy04ahzeQYDzIwMjMwODE2MDk1NDM2WjADAgEeoIGGpIGDMIGAMQsw
# CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV
# BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNI
# QTI1NiBUaW1lU3RhbXBpbmcgU2lnbmVyIC0gRzOgggqLMIIFODCCBCCgAwIBAgIQ
# ewWx1EloUUT3yYnSnBmdEjANBgkqhkiG9w0BAQsFADCBvTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVz
# dCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwOCBWZXJpU2lnbiwgSW5jLiAtIEZv
# ciBhdXRob3JpemVkIHVzZSBvbmx5MTgwNgYDVQQDEy9WZXJpU2lnbiBVbml2ZXJz
# YWwgUm9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNjAxMTIwMDAwMDBa
# Fw0zMTAxMTEyMzU5NTlaMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEo
# MCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBALtZnVlVT52Mcl0agaLrVfOwAa08cawy
# jwVrhponADKXak3JZBRLKbvC2Sm5Luxjs+HPPwtWkPhiG37rpgfi3n9ebUA41JEG
# 50F8eRzLy60bv9iVkfPw7mz4rZY5Ln/BJ7h4OcWEpe3tr4eOzo3HberSmLU6Hx45
# ncP0mqj0hOHE0XxxxgYptD/kgw0mw3sIPk35CrczSf/KO9T1sptL4YiZGvXA6TMU
# 1t/HgNuR7v68kldyd/TNqMz+CfWTN76ViGrF3PSxS9TO6AmRX7WEeTWKeKwZMo8j
# wTJBG1kOqT6xzPnWK++32OTVHW0ROpL2k8mc40juu1MO1DaXhnjFoTcCAwEAAaOC
# AXcwggFzMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMGYGA1Ud
# IARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9y
# cGEwLgYIKwYBBQUHAQEEIjAgMB4GCCsGAQUFBzABhhJodHRwOi8vcy5zeW1jZC5j
# b20wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3Muc3ltY2IuY29tL3VuaXZlcnNh
# bC1yb290LmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAoBgNVHREEITAfpB0wGzEZ
# MBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMzAdBgNVHQ4EFgQUr2PWyqNOhXLgp7xB
# 8ymiOH+AdWIwHwYDVR0jBBgwFoAUtnf6aUhHn1MS1cLqBzJ2B9GXBxkwDQYJKoZI
# hvcNAQELBQADggEBAHXqsC3VNBlcMkX+DuHUT6Z4wW/X6t3cT/OhyIGI96ePFeZA
# Ka3mXfSi2VZkhHEwKt0eYRdmIFYGmBmNXXHy+Je8Cf0ckUfJ4uiNA/vMkC/WCmxO
# M+zWtJPITJBjSDlAIcTd1m6JmDy1mJfoqQa3CcmPU1dBkC/hHk1O3MoQeGxCbvC2
# xfhhXFL1TvZrjfdKer7zzf0D19n2A6gP41P3CnXsxnUuqmaFBJm3+AZX4cYO9uiv
# 2uybGB+queM6AL/OipTLAduexzi7D1Kr0eOUA2AKTaD+J20UMvw/l0Dhv5mJ2+Q5
# FL3a5NPD6itas5VYVQR9x5rsIwONhSrS/66pYYEwggVLMIIEM6ADAgECAhB71OWv
# uswHP6EBIwQiQU0SMA0GCSqGSIb3DQEBCwUAMHcxCzAJBgNVBAYTAlVTMR0wGwYD
# VQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1
# c3QgTmV0d29yazEoMCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQTAeFw0xNzEyMjMwMDAwMDBaFw0yOTAzMjIyMzU5NTlaMIGAMQswCQYDVQQG
# EwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5
# bWFudGVjIFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNIQTI1NiBU
# aW1lU3RhbXBpbmcgU2lnbmVyIC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQCvDoqq+Ny/aXtUF3FHCb2NPIH4dBV3Z5Cc/d5OAp5LdvblNj5l1SQg
# bTD53R2D6T8nSjNObRaK5I1AjSKqvqcLG9IHtjy1GiQo+BtyUT3ICYgmCDr5+kMj
# dUdwDLNfW48IHXJIV2VNrwI8QPf03TI4kz/lLKbzWSPLgN4TTfkQyaoKGGxVYVfR
# 8QIsxLWr8mwj0p8NDxlsrYViaf1OhcGKUjGrW9jJdFLjV2wiv1V/b8oGqz9KtyJ2
# ZezsNvKWlYEmLP27mKoBONOvJUCbCVPwKVeFWF7qhUhBIYfl3rTTJrJ7QFNYeY5S
# MQZNlANFxM48A+y3API6IsW0b+XvsIqbAgMBAAGjggHHMIIBwzAMBgNVHRMBAf8E
# AjAAMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0
# cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5
# bWNiLmNvbS9ycGEwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cDovL3RzLWNybC53cy5z
# eW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jcmwwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwDgYDVR0PAQH/BAQDAgeAMHcGCCsGAQUFBwEBBGswaTAqBggrBgEFBQcw
# AYYeaHR0cDovL3RzLW9jc3Aud3Muc3ltYW50ZWMuY29tMDsGCCsGAQUFBzAChi9o
# dHRwOi8vdHMtYWlhLndzLnN5bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNlcjAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtNjAdBgNVHQ4E
# FgQUpRMBqZ+FzBtuFh5fOzGqeTYAex0wHwYDVR0jBBgwFoAUr2PWyqNOhXLgp7xB
# 8ymiOH+AdWIwDQYJKoZIhvcNAQELBQADggEBAEaer/C4ol+imUjPqCdLIc2yuaZy
# cGMv41UpezlGTud+ZQZYi7xXipINCNgQujYk+gp7+zvTYr9KlBXmgtuKVG3/KP5n
# z3E/5jMJ2aJZEPQeSv5lzN7Ua+NSKXUASiulzMub6KlN97QXWZJBw7c/hub2wH9E
# PEZcF1rjpDvVaSbVIX3hgGd+Yqy3Ti4VmuWcI69bEepxqUH5DXk4qaENz7Sx2j6a
# escixXTN30cJhsT8kSWyG5bphQjo3ep0YG5gpVZ6DchEWNzm+UgUnuW/3gC9d7GY
# FHIUJN/HESwfAD/DSxTGZxzMHgajkF9cVIs+4zNbgg/Ft4YCTnGf6WZFP3YxggJa
# MIICVgIBATCBizB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNV
# BAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEHvU5a+6zAc/oQEj
# BCJBTRIwCwYJYIZIAWUDBAIBoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMjMwODE2MDk1NDM2WjAvBgkqhkiG9w0BCQQxIgQg
# Dn1eYREAX3OlfFroagv4eSq9L50UsojBvhebmYHF72wwNwYLKoZIhvcNAQkQAi8x
# KDAmMCQwIgQgxHTOdgB9AjlODaXk3nwUxoD54oIBPP72U+9dtx/fYfgwCwYJKoZI
# hvcNAQEBBIIBAHZMGX03xeq1JXn6aTN5zCxXlHpJWGvCg6nwRJlvhvXBp0w7Oq0m
# xVMrAocsJgti+he8PEJ+izLDRJ6K77B/i5wPkdisNzlCTCNjWtNbaOgq1Copwcw3
# 1HFdatwkKD6/3PT1nPb6W/HLHk/MuiH7GLDEpVooSt1kXNEw1tvwTTWncPJC7DZ4
# QbOUz4u/zzGBTAysWjFpVfff0McpchP0kVRm9uJqfY/Xr5iVd5iRec1QKpLBisda
# FTH3Th+9vvrJcAbpTrYAzvGoEe98cWhM43RR1VlmFcjcwY/iL52HpbrFtV7YSIBk
# 03yGAv6gfhPSFnTnwwUEaBm3Ndt0bqjgsCY=
# SIG # End signature block
