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

    [Parameter(Mandatory=$false)]
    [Switch]$skipTLS,

    [Parameter(Mandatory = $false, HelpMessage = "Specify a User that has Privilege Cloud Administrative permissions.")]
    [PSCredential]$Credentials,

    [Parameter(Mandatory=$false)]
    [Switch]$SkipCertVerification
)


$Host.UI.RawUI.WindowTitle = "Privilege Cloud CreateCredFile-Helper"
$Script:LOG_FILE_PATH = "$PSScriptRoot\_CreateCredFile-Helper.log"
$global:CPMnewSyncToolFolder = "$PSScriptRoot\CreateCredFile-HelperDependencies"
$ScriptVersion = "5.1"

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

Function Collect-ExceptionMessage {
    param(
        [Exception]$e
    )

    Begin {
    }

    Process {
        $msg = "Source: {0}; Message: {1}" -f $e.Source, $e.Message
        while ($e.InnerException) {
            $e = $e.InnerException
            $msg += "`n`tSource: {0}; Message: {1}" -f $e.Source, $e.Message
        }
        return $msg
    }

    End {
    }
}



#endregion


#region Check latest version
$Script:GitHubAPIURL = "https://api.github.com/repos"

Function Test-ScriptLatestVersion
{
    [CmdletBinding()]
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
    $isLatestVersion = $false
    try{
        $getScriptContent = (Invoke-WebRequest -UseBasicParsing -Uri $fileURL).Content
        if($getScriptContent -match "$versionPattern\s{0,1}=\s{0,1}`"([\d\.]{1,10})`"")
        {
            $gitHubScriptVersion = $Matches[1]
            if($null -ne $outGitHubVersion)
            {
                $outGitHubVersion.Value = $gitHubScriptVersion
            }
            Write-LogMessage -type Verbose -msg "Current Version: $currentVersion; GitHub Version: $gitHubScriptVersion"
            $gitHubMajorMinor = [double]($gitHubScriptVersion.Split(".")[0..1] -join '.')
            $currentMajorMinor = [double]($currentVersion.Split(".")[0..1] -join '.')
            $gitHubPatch = 0
            $currentPatch = 0
            if(($gitHubScriptVersion.Split(".").Count -gt 2) -or ($currentVersion.Split(".").Count -gt 2))
            {
                $gitHubPatch = [int]($gitHubScriptVersion.Split(".")[2])
                $currentPatch = [int]($currentVersion.Split(".")[2])
            }
            if($gitHubMajorMinor -gt $currentMajorMinor)
            {
                $isLatestVersion = $true
            }
            elseif($gitHubMajorMinor -eq $currentMajorMinor -and $gitHubPatch -gt $currentPatch)
            {
                $isLatestVersion = $true
            }
        }
        else
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

Function Copy-GitHubContent
{
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
                $itemDir = Join-Path -Path $outputFolderPath -ChildPath $item.name
                if(! (Test-Path -path $itemDir))
                {
                    New-Item -ItemType Directory -Path $itemDir | Out-Null
                }
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
            $destPath = Split-Path -Path $item.FullName.Replace($Path, $Destination) -Parent
            $oldName = "$($item.Name).OLD"
            if(Test-Path -Path $(Join-Path -Path $destPath -ChildPath $item.Name))
            {
                Rename-Item -Path $(Join-Path -Path $destPath -ChildPath $item.Name) -NewName $oldName
                Copy-Item -Path $item.FullName -Destination $(Join-Path -Path $destPath -ChildPath $item.Name)
                Remove-Item -Path $(Join-Path -Path $destPath -ChildPath $oldName)
            }
            else
            {
                Write-Error "Can't find file $($item.Name) in destination location '$destPath' to replace, copying"
                Copy-Item -Path $item.FullName -Destination $destPath
            }
        }
    }
    catch{
        Throw $(New-Object System.Exception ("Replace-Item: Couldn't Replace files",$_.Exception))
    }
}

Function Test-GitHubLatestVersion
{
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
        return $true
    }

    try{
        if($shouldDownloadLatestVersion -eq $true)
        {
            $retLatestVersion = $false
            if(! $TestOnly)
            {
                Write-LogMessage -type Info -Msg "Found new version (version $gitHubVersion), Updating..."
                $tmpFolder = Join-Path -Path $sourceFolderPath -ChildPath "tmp"
                if(! (Test-Path -Path $tmpFolder))
                {
                    New-Item -ItemType Directory -Path $tmpFolder | Out-Null
                }
                try{
                    Copy-GitHubContent -outputFolderPath $tmpFolder -gitHubItemURL $apiURL
                    Replace-Item -Recurse -Path $tmpFolder -Destination $sourceFolderPath
                    Remove-Item -Recurse -Path $tmpFolder -Force
                }
                catch
                {
                    $retLatestVersion = $true
                    Write-Error -Message "There was an error downloading GitHub content." -Exception $_.Exception
                }
            }
            else {
                Write-LogMessage -type Info -Msg "Found a new version in GitHub (version $gitHubVersion), skipping update"
            }
        }
        else
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
Function Get-Choice {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]
        $Options,

        [Parameter(Position = 2)]
        $DefaultChoice = -1
    )

    # Check if running on macOS
    if ($IsMacOS -or ($PSVersionTable.OS -match "Unix" -and !(Test-Path Env:OS -Value "Windows_NT"))) {
        if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 0)) {
            Write-Warning "DefaultChoice needs to be a value between 0 and $($Options.Count - 1) or -1 (for none)"
            return
        }

        Write-Host "$Title`n"

        for ($i = 0; $i -lt $Options.Length; $i++) {
            Write-Host "$($i+1): $($Options[$i])"
        }

        $choice = $DefaultChoice
        if ($DefaultChoice -eq -1) {
            do {
                $input = Read-Host "Please select an option (1-$($Options.Length))"
                if ($input -match '^\d+$') {
                    $choice = [int]$input - 1
                }
            }
            while ($choice -lt 0 -or $choice -ge $Options.Length)
        }

        return $Options[$choice]
    } else {
        # Original GUI-based logic for Windows
        if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1)) {
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
        # Calculate width required based on longest option text and form title
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
        # Create the buttons dynamically based on the options
        foreach ($option in $Options) {
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
        if ($DefaultChoice -ne -1) {
            $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()'
        }
        $shownSB = [ScriptBlock]::Create($shownString)
        $form.Add_Shown($shownSB)
        [void]$form.ShowDialog()
        return $result
    }
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
function Get-ServiceInstallPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    try {
        # Construct the registry path for the service.
        $regKeyPath = "HKLM:\System\CurrentControlSet\Services\$ServiceName"

        # Retrieve the service registry key properties.
        $serviceProps = Get-ItemProperty -Path $regKeyPath -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($serviceProps.ImagePath)) {
            Write-LogMessage -type Verbose -MSG "Service '$ServiceName' does not have an ImagePath defined."
            return $null
        }

        $imagePath = $serviceProps.ImagePath.Trim()

        # If the ImagePath starts with quotes, extract the content inside quotes.
        if ($imagePath.StartsWith('"')) {
            if ($imagePath -match '^"([^"]+)"') {
                return $matches[1]
            } else {
                Write-LogMessage -type Verbose -MSG "Unable to extract the executable path from quoted ImagePath: $imagePath"
                return $imagePath
            }
        } else {
            # If the path isn�t quoted, assume the executable path is the first token.
            return $imagePath.Split(" ")[0]
        }
    }
    catch {
        Write-LogMessage -type Verbose -MSG "Error retrieving install path for service '$ServiceName': $_"
        return $null
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
							$fileVersion = [version](Get-FileVersion "$cpmPath\PMEngine.exe")
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
							$myObject = New-Object PSObject -Property @{Name="CPM";DisplayName="CyberArk Password Manager (CPM) $fileVersion";
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
							$fileVersion = [version](Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe")
                            $ServiceLogs = @()
                            $ComponentUser = @()
                            $ConfigPath = ""
                            $myObject = New-Object PSObject -Property @{Name="PVWA";DisplayName="CyberArk Password Vault Web Application (PVWA) $fileVersion";
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
                            # handle old and new psm
                            $psmCandidates = @($REGKEY_PSMSERVICEold, $REGKEY_PSMSERVICEnew)
                            $componentPath = $null
                            foreach ($candidate in $psmCandidates) {
                                $foundPath = Get-ServiceInstallPath $candidate
                                if ($foundPath) {
                                    $componentPath = $foundPath
                                    $REGKEY_PSMSERVICE = $candidate
                                break
                                }
                            }
                            # If no valid install found, exit switch
                            if (-not $componentPath) {
                                Write-LogMessage -Type "Debug" -MSG "PSM service not found. Skipping PSM detection."
                                break
                            }
                            Write-LogMessage -Type "Info" -MSG "Found PSM installation"
							$PSMPath = $componentPath.Replace("CAPSM.exe","").Replace('"',"").Trim()
                            $ConfigPath = (Join-Path -Path $PSMPath -ChildPath "temp\PVConfiguration.xml")
							$fileVersion = [version](Get-FileVersion "$PSMPath\CAPSM.exe")
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
                            $myObject = New-Object PSObject -Property @{Name="PSM";DisplayName="CyberArk Privileged Session Manager (PSM) $fileVersion";
                                                                        ServiceName=$REGKEY_PSMSERVICE;Path=$PSMPath;Version=$fileVersion;
                                                                        ComponentUser=$ComponentUser;ConfigPath=$ConfigPath;ServiceLogs=$ServiceLogs;UserType=$UserType}
                            $myObject | Add-Member -MemberType ScriptMethod -Name InitPVWAURL -Value { Set-PVWAURL -ComponentID $this.Name -ConfigPath $this.ConfigPath -AuthType $AuthType} | Out-Null
                            return $myObject
						
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
							$fileVersion = [version](Get-FileVersion "$AIMPath\AppProvider.exe")
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
                            $myObject = New-Object PSObject -Property @{Name="AIM";DisplayName="CyberArk Application Password Provider (AIM) $fileVersion";
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
                        if (($GetPVWAStringURL -like "vault-*.cyberark.com") -or ($GetPVWAStringURL -like "*vault-*.cyberark.cloud")){
                            # grab first subdomain and trim vault- from it.
                            $portalSubDomainURL = $GetPVWAStringURL.Split(".")[0] -replace '^vault-', ''
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
            # Check pcloud format
            if($PVWAurl -notmatch "\.privilegecloud\.cyberark."){
                Write-LogMessage -type Warning -MSG "Warning: URL entered doesn't seem to have Privilege Cloud Format (Missing `"privilegecloud`" in the string)"
                $PVWAurl = $PVWAurl -replace "(\.cyberark\.)", ".privilegecloud.cyberark."
                Write-LogMessage -type Info -MSG "Let's rebuild the URL: $PVWAurl"
            }
        }
		
		# Let user confirm this is the correct URL, otherwise, enter manually
        $confirmPVWAUrl = Get-Choice -Title "Is this your Portal URL: $PVWAurl" -Options "Yes", "No, let me type." -DefaultChoice 1
        if($confirmPVWAUrl -eq "No, let me type."){
            $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
        }

        Write-LogMessage -type debug -Msg "The PVWA URL to be used is: '$PVWAurl'"
    } Catch{
        Write-LogMessage -type Error -MSG "There was an error reading the $ComponentID configuration file '$ConfigPath': $($_.Exception.Message)"
        Write-LogMessage -type Info -MSG "Couldn't retrieve portal URL from configuration file, let's type it manually:"
        $PVWAurl = (Read-Host "Enter your Portal URL (eg; 'https://mikeb.privilegecloud.cyberark.com' or https://mikeb.privilegecloud.cyberark.cloud)")
    }
    
    # Set the PVWA URLS
    $URL_PVWA = "https://"+([System.Uri]$PVWAurl).Host
    $URL_PVWAPasswordVault = $URL_PVWA+"/passwordVault"
    $global:URL_PVWAAPI = $URL_PVWAPasswordVault+"/api"
    $URL_PVWAAuthentication = $URL_PVWAAPI+"/auth"
    $script:URL_PVWALogon = $URL_PVWAAuthentication+"/$AuthType/Logon"
    $script:URL_PVWALogoff = $URL_PVWAAuthentication+"/Logoff"
    Write-LogMessage -type info -Msg "Logon URL will be: '$URL_PVWALogon'"
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
    if(-not($Credentials)){
        [PSCredential]$script:Credentials = $Host.UI.PromptForCredential($caption,$msg,"","")
    }
    try{
        # Login to PVWA
        Write-LogMessage -type Info -MSG "Logging in with user: $($Credentials.UserName)"
        $global:pvwaLogonHeader = Get-LogonHeader -Credentials $Credentials
    } catch {
        Throw $(New-Object System.Exception ("Error logging on to PVWA",$_.Exception))
    }
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
        Write-LogMessage -type Info -MSG "Starting service '$ServiceName'..."
        #Check If need to Stop CPM or PSM
        $CAStarted = "Started"
        $CAStart = "Start"
        $CARunning = "Running"
        $Service = Get-Service $ServiceName
        $service.Start()
        $Service.WaitForStatus($CARunning,'00:01:59')
        $service.refresh()
        $ServiceStatus = Get-Service -Name $Service.Name | Select-Object -ExpandProperty status
        if($ServiceStatus -eq $CARunning){
            Write-LogMessage -type success -Msg "Successfully $CAStarted Service: $($service.name)."
        }
        Else{
            Write-LogMessage -type Warning -Msg "Couldn't $CAStart Service: $($service.name) Do it Manually."
        }
    } catch {
        Throw $(New-Object System.Exception ("Error starting the service '$ServiceName'. Check Service Status and start it Manually (Also check local Console or Trace logs)."))
    }
}

Function enforceTLS {
    # Check the current SecurityProtocol setting
    $securityProtocol = [Net.ServicePointManager]::SecurityProtocol
	if ($securityProtocol -ne 'SystemDefault' -and $securityProtocol -notmatch 'Tls12') {
        Write-LogMessage -type Info -MSG "Detected SecurityProtocol not highest settings ('$($securityProtocol)'), enforcing TLS 1.2."
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	}
        # Registry checks for .NET Framework strong cryptography settings
        $GetTLSReg86 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        $GetTLSReg64 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        
        # Registry checks for TLS 1.2 being explicitly disabled in Client and Server
        $Gettls12ClientValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -ErrorAction SilentlyContinue
        $Gettls12ServerValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue

        $gettls12ClientDefaultDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -ErrorAction SilentlyContinue
        $gettls12ServerDefaultDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -ErrorAction SilentlyContinue

        $TLSReg86 = $GetTLSReg86 -ne $null -and $GetTLSReg86.SchUseStrongCrypto -eq 0
        $TLSReg64 = $GetTLSReg64 -ne $null -and $GetTLSReg64.SchUseStrongCrypto -eq 0
        $tls12ClientValue = $Gettls12ClientValue -ne $null -and $Gettls12ClientValue.Enabled -eq 0
        $tls12ServerValue = $Gettls12ServerValue -ne $null -and $Gettls12ServerValue.Enabled -eq 0
        $tls12ClientDefaultDisabled = $gettls12ClientDefaultDisabled -ne $null -and $gettls12ClientDefaultDisabled.DisabledByDefault -eq 1
        $tls12ServerDefaultDisabled = $gettls12ServerDefaultDisabled -ne $null -and $gettls12ServerDefaultDisabled.DisabledByDefault -eq 1

        if ($TLSReg86 -or $TLSReg64 -or $tls12ClientValue -or $tls12ServerValue -or $tls12ClientDefaultDisabled -or $tls12ServerDefaultDisabled) {
            Write-LogMessage -Type Info -MSG "Adjusting settings to ensure TLS 1.2 is not explicitly disabled and strong cryptography is enforced."
            if ($TLSReg86) {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -Verbose
            }
            if ($TLSReg64) {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ClientValue) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ServerValue) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ClientDefaultDisabled) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -Type DWord -Force -Verbose
            }
            if ($tls12ServerDefaultDisabled) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord -Force -Verbose
            }

            Write-LogMessage -Type Warning -MSG "Settings adjusted. Please RESTART the system for the changes to take effect."
            Write-LogMessage -Type Warning -MSG "If this check keeps looping, you can skip it with -skipTLS flag when running the script."
			Pause
			Exit
        } else {
            Write-LogMessage -Type Info -MSG "TLS 1.2 is properly configured."
        }
}

Function IgnoreCert {
    param(
        [bool]$SkipCertVerification = $false # Add a parameter to control certificate verification skipping
    )

    # Your existing logic to check and enforce TLS 1.2 settings

    if ($SkipCertVerification) {
        # The portion of the script that ignores certificate errors
        Write-LogMessage -Type Info -MSG "Skipping certificate verification as per script parameter."
        if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
            $certCallback = @"
                using System;
                using System.Net;
                using System.Net.Security;
                using System.Security.Cryptography.X509Certificates;
                public class ServerCertificateValidationCallback
                {
                    public static void Ignore()
                    {
                        if (ServicePointManager.ServerCertificateValidationCallback == null)
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
    
    # This line ensures TLS 1.2 is used for future requests. Consider the context and necessity as per earlier discussion.
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
    Start-Sleep -Seconds 7
    # Check the log is not empty
    if (![string]::IsNullOrEmpty($(Get-Content -Path $LogPath)) -and (Select-String -Path $LogPath -Pattern "error" -Quiet))
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

Function Format-URL($sText) {
	if ($sText.Trim() -ne "") {
		return [System.Web.HttpUtility]::UrlEncode($sText.Trim())
	}
	else {
		return ""
	}
}

Function New-SearchCriteria {
	param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [int]$iLimitPage, [int]$iOffsetPage = 0)
	[string]$retURL = $sURL
	$retURL += "?"
	
	if (![string]::IsNullOrEmpty($sSearch)) {
		$retURL += "search=$(Format-URL $sSearch)&"
	}
	if (![string]::IsNullOrEmpty($sSafeName)) {
		$retURL += "filter=safename eq $(Format-URL $sSafeName)&"
	}
	if (![string]::IsNullOrEmpty($sSortParam)) {
		$retURL += "sort=$(Format-URL $sSortParam)&"
	}
	if ($iLimitPage -gt 0) {
		$retURL += "limit=$iLimitPage&"
	}
		
	if ($retURL[-1] -eq '&') {
		$retURL = $retURL.substring(0, $retURL.length - 1) 
 }
	return $retURL
}

Function Get-Account{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccountName,

        [Parameter(Mandatory=$true)]
        [string]$URLAPI,

        [Parameter(Mandatory=$true)]
        $logonheader,

        [Parameter(Mandatory=$true)]
        [string]$SafeName,

        [Parameter(Mandatory=$true)]
        [int]$limitPage
    )

    $limitPage = 0
    $URL_Accounts = $URLAPI + "/Accounts"
    
    $AccountsURLWithFilters = ""
    $AccountsURLWithFilters = $(New-SearchCriteria -sURL $URL_Accounts -sSearch $AccountName -sSafeName $SafeName -iLimitPage $limitPage)    

    Try
    {
        #Write-LogMessage -Type Info -Msg "Calling: $($AccountsURLWithFilters)"
        Write-LogMessage -type Info -MSG "Looking for account $AccountName in vault under safe: '$SafeName'"
        $GetAccountsResponse = Invoke-RestMethod -Method Get -Uri $AccountsURLWithFilters -Headers $logonheader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable pvwaERR
        return $GetAccountsResponse
    }
    Catch
    {
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
    }
}


Function Get-AccountPassword{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccountID,

        [Parameter(Mandatory=$true)]
        [string]$URLAPI,

        [Parameter(Mandatory=$true)]
        $logonheader
    )

    $URL_Accounts = $URLAPI + "/Accounts"
    $URL_AccountPW = "$URL_Accounts/$AccountID/Password/Retrieve"

    Try
    {
        #Write-LogMessage -Type Info -Msg "Calling: $($URL_AccountPW)"

        $bodyReason = @{ reason = "User ran pcloudtools API script" } | ConvertTo-Json
        Write-LogMessage -type Info -MSG "Retrieving account password"
        $GetAccountPassword = Invoke-RestMethod -Method POST -Uri $URL_AccountPW -Headers $logonheader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable pvwaERR -Body $bodyReason
        return $GetAccountPassword
    }
    Catch{
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
    }
}

function Reset-LocalUserPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Check for admin rights
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-LogMessage -type Error -MSG "This script requires administrative privileges. Please run PowerShell as an administrator."
        pause
        exit
    }

    try {
        $Username = $Credential.UserName
        # Check if the user exists
        $userExists = Get-LocalUser | Where-Object { $_.Name -eq $Username }
        if (-not $userExists) {
            Write-LogMessage -type Error -MSG "User '$Username' does not exist."
            return
        }

        $securePassword = $Credential.Password
        Set-LocalUser -Name $Username -Password $securePassword
        Write-LogMessage -type Success -MSG "Password for user '$Username' has been reset successfully."
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to reset password for user '$Username'. Error: $_"
    }
}

function Test-Credential {
	param(
		[parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[System.Management.Automation.PSCredential]$credential,
		[parameter()][validateset('Domain','Machine')]
		[string]$context = 'Domain'
	)
	begin {
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::$context) 
	}
	process {
		$DS.ValidateCredentials($credential.GetNetworkCredential().UserName, $credential.GetNetworkCredential().password)
	}
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
        $ComponentUser = $ComponentUser.Trim()
        if ([string]::IsNullOrWhiteSpace($ComponentUser)) {
            throw "Component user is empty. Cannot generate CredFile '$FileName'."
        }
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
            If ($ComponentID -eq "AIM") { $appType = "AIMProvider" }
            & "$ComponentPath\Vault\CreateCredFile.exe" "$FileName" Password /username $ComponentUser /Password $GetComponentUserDetailsNewPW /AppType $appType
        }
        if (-not (Test-Path -LiteralPath $FileName)) {
            throw "CreateCredFile.exe did not create file '$FileName'."
        }
        $credFileInfo = Get-Item -LiteralPath $FileName
        if ($credFileInfo.Length -eq 0) {
            throw "CreateCredFile.exe created an empty file '$FileName'."
        }
    } catch {
        Throw $(New-Object System.Exception ("Error generating CredFile for file '$FileName'.",$_.Exception))
    }
}



Function ResetCPMUserandAPIkeyNewMethdod(){ # Should only use from CPM 14.2+ since
param(
    [PSCredential]$Credentials,
    [string]$cpmPAth,
    [string]$apiUser
)


    $ComponentConfig = @{
        VaultIniPath = "$($cpmPAth)Vault\Vault.ini"
        Component = "cpm"
        ComponentUsers = @(
            @{
                GenerateCredFile = $true
                CredFilePath = "$($cpmPAth)Vault\user.ini"
                APIGWFilePath = "$($cpmPAth)Vault\apikey.ini"
                DisplayName = "CPM app user"
                CompDefaultUsername = "$apiUser"
            }
        )
        vaultAdminUsername = "$($Credentials.Username)"
    }
    
    # Generate the JSON input file
    $InputFile = "$CPMnewSyncToolFolder\SyncCompUsersInput.json"
    $jsonContent = $ComponentConfig | ConvertTo-Json -Depth 3
    
    # Ensure the folder exists and overwrite the file if it exists
    $InputFolder = [System.IO.Path]::GetDirectoryName($InputFile)
    if (-not (Test-Path $InputFolder)) {
        New-Item -Path $InputFolder -ItemType Directory | Out-Null
    }
    Set-Content -Path $InputFile -Value $jsonContent
    
    function RunProcess {
        param (
            [Parameter(Mandatory=$true)]
            [string]$ProcessFullPath,
    
            [Parameter(Mandatory=$false)]
            [string[]]$Args,

            [Parameter(Mandatory=$false)]
            [string]$ComponentUser
    
        )
        begin {
            $processName = Split-Path -Leaf $ProcessFullPath
            $processPath = Split-Path -Parent $ProcessFullPath
        }
        process {
            $processArgs = ""
            foreach ($item in $Args) {
                $processArgs += "`"$item`" "
            }

            if ([string]::IsNullOrWhiteSpace($ComponentUser)) {
                Write-LogMessage -type Info -MSG "Running $processName..."
            }
            else {
                Write-LogMessage -type Info -MSG "Running $processName for user '$ComponentUser'..."
            }

            [System.Environment]::SetEnvironmentVariable('VAULT_PASSWORD', $Credentials.GetNetworkCredential().Password)

            try {
                $process = (Start-Process -FilePath $ProcessFullPath -ArgumentList $processArgs -WorkingDirectory $processPath -Wait -WindowStyle Hidden -PassThru)
            }
            finally {
                [System.Environment]::SetEnvironmentVariable('VAULT_PASSWORD', $null)
            }

            $processExitCode = $process.ExitCode.ToString()
            [bool]$isSuccess = $false
            if ($process.ExitCode -eq 0) {
                Write-LogMessage -type Success -MSG "Process $processName finished successfully"
                if (-not [string]::IsNullOrWhiteSpace($ComponentUser)) {
                    Write-LogMessage -type Success -MSG "Successfully synced CPM user '$ComponentUser'."
                }
            }
            else {
                Write-LogMessage -type Error -MSG "Process $processName failed with exit code $processExitCode"
                Write-LogMessage -type Error -MSG "More info here: $CPMnewSyncToolFolder\Log\SyncCompUsers.log"
            }
        }
    }
    
    
    try {
    
        $args = @($InputFile, "yes")
        $ExecutableFullPath = Resolve-Path $CPMnewSyncToolFolder\SyncCompUsers.exe
    
        RunProcess -ProcessFullPath $ExecutableFullPath -Args $args -ComponentUser $apiUser
    }
    catch {
        Write-LogMessage -type Error -MSG "Failed to sync component users."
        Write-LogMessage -type Error -MSG "$($_.Exception)"
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
                        Write-LogMessage -Type Success -MSG "Found a match between an offline component user '$foundUser' and local logs, will use it to generate CredFile."
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
                    Write-LogMessage -Type Warning -MSG "Couldn't match offline component user in SystemHealth in local Logs, will have to input manually."
                    do {
                        $ComponentUser = (Read-Host "Enter the relevant user name for CredFile: '$credFile'").Trim()
                        if ([string]::IsNullOrWhiteSpace($ComponentUser)) {
                            Write-LogMessage -Type Warning -MSG "No user name was entered. Please enter a valid component user name."
                        }
                    } while ([string]::IsNullOrWhiteSpace($ComponentUser))
                }
            }
            Invoke-GenerateCredFile @generateCredFileParameters -FileName $credFile -ComponentUser $ComponentUser
            # Reset User pw in the vault and activate it
            Get-UserAndResetPassword -ComponentUser $ComponentUser -UserType $Component.UserType -NewPassword $generatedPassword
            #expose variable for apikey reset function.
			if(-not($ComponentUser -like "PSMGw_*"))
			{ # if PSM user is GW skip it from being exposed for apikey use.
				$global:apiKeyUsername = $ComponentUser
				$global:apiKeyPath = $Component.Path
			}

        }
        # For cases where there is more than one service to start
        Foreach($svc in $Component.ServiceName)
        {
            if (-not($svc -eq "CyberArk Central Policy Manager Scanner")){
                Start-CYBRService -ServiceName $svc
            }
        }
        
        Get-SystemHealth -componentUserDetails $(Get-CredFileUser -File $Component.ComponentUser[0]) -ComponentID $Component.Name
        #Test-SystemLogs -ComponentID $Component.Name -LogPath $Component.serviceLogs[0] | Out-Null
        #Invoke-Logoff
    } catch {
        Throw $(New-Object System.Exception ("Error in the flow of Resetting component $($Component.Name) credentials file.",$_.Exception))
    }
}

Function Resolve-ComponentUserForCredFile
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [PSObject]$Component,
        [Parameter(Mandatory=$true)]
        [string]$CredFile
    )

    $ComponentUser = $(Get-CredFileUser -File $CredFile)
    if([string]::IsNullOrEmpty($ComponentUser))
    {
        Write-LogMessage -Type Info -MSG "Could not find Component User from CredFile, trying to look for all offline components"
        $offlineComponents = $(Get-SystemHealth -ComponentID $Component.Name -OfflineOnly)
        Foreach($user in $offlineComponents)
        {
            $foundUser = $(Find-UserInSystemLogs -User $User.ComponentUserName -LogPaths $Component.ServiceLogs)
            If(! [string]::IsNullOrEmpty($foundUser)){
                Write-LogMessage -Type Success -MSG "Found a match between an offline component user '$foundUser' and local logs, will use it to generate CredFile."
                $ComponentUser = $foundUser
                if ($CredFile -like "*psmgw.cred*"){
                    $ComponentUser = "PSMGw_"+$foundUser.split("_")[1]
                }
                Break
            }
        }
        If($offlineComponents.Count -eq 0 -or [string]::IsNullOrWhiteSpace($ComponentUser))
        {
            Write-LogMessage -Type Warning -MSG "Couldn't match offline component user in SystemHealth in local Logs, will have to input manually."
            do {
                $ComponentUser = (Read-Host "Enter the relevant user name for CredFile: '$CredFile'").Trim()
                if ([string]::IsNullOrWhiteSpace($ComponentUser)) {
                    Write-LogMessage -Type Warning -MSG "No user name was entered. Please enter a valid component user name."
                }
            } while ([string]::IsNullOrWhiteSpace($ComponentUser))
        }
    }

    return $ComponentUser
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

# @FUNCTION@ ======================================================================================================================
# Name...........: Add-CALocalUser
# Description....: Creates a new local user using the username, password and description submitted 
# Parameters.....: $userName - The username of user to create
#                  $userPassword - The user password
#                  $userDescription - The user description of user to create
# Return Values..: $true or $false
# =================================================================================================================================
function Add-CALocalUser{
	[CmdletBinding()] 
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$userName,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()][System.Security.SecureString]$userPassword,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$userDescription
   )
     	Process {
		Try{
            $result = $false
			   Write-LogMessage -Type Info -MSG "Attempting to create new local user $userName"

            $localComputer = [ADSI]"WinNT://$env:COMPUTERNAME"
            $existingUser = $localComputer.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $userName }

            if ($existingUser -eq $null) {
      
				$user = $localComputer.Create("User", $userName)
				
				$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($userPassword)
	            $user.SetPassword([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
	            $user.SetInfo()
				[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
	       
	            $user.Put("Description", $userDescription)
	            $user.SetInfo()
               Write-LogMessage -Type Info -MSG "The local user $userName has been successfully created"
            }
            else {
                Write-LogMessage -Type Info -MSG "Local user $userName is already exists."
            }

		}Catch{
            Write-LogMessage -Type "Error" -Msg "Error: $(Join-ExceptionMessage $_.Exception)"
		}
	}
	End{
   }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: New-CANewAccessControlObject
# Description....: Get the relevant access control object for this path.
# Parameters.....: $path - The location path we want to set permissions.
#				   $identity - The identity we want to set the relevant permissions.
#				   $rights - The rights we want to set to the identity on this path.
#							 Please Notice this needs to be string indicate enum name from System.Security.AccessControl.RegistryRights or System.Security.AccessControl.FileSystemRights enums.
# Return Values..: $NUll is couldn't create object, otherwise it return the relevant object.
# =================================================================================================================================
function New-CANewAccessControlObject{
   [CmdletBinding()] 
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$path,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$identity,
   [ValidateNotNullOrEmpty()]$rights
   )
	Process {
		$returnVal = $NULL
		try {
			$item = Get-Item -Path $path
			
			If ($item -is [System.IO.DirectoryInfo]) {
				$returnVal = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$rights,"ContainerInherit,ObjectInherit","None","Allow")
			} ElseIf ($item -is [Microsoft.Win32.RegistryKey]) {
				$returnVal = New-Object System.Security.AccessControl.RegistryAccessRule ($identity,$rights,"ContainerInherit,ObjectInherit","None","Allow")
			} ElseIf ($item -is [System.IO.FileInfo]){
				$returnVal = New-Object System.Security.AccessControl.FileSystemAccessRule ($identity,$rights,"Allow")
			}
		} Catch {
			Write-LogMessage -Type "Error" -Msg "Error: $(Join-ExceptionMessage $_.Exception)"
		}
		return $returnVal
	}
	End{
   }
}


function Set-CAPermissions{
   [CmdletBinding()] 
   param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$path,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$identity,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$rights,
   [ValidateNotNullOrEmpty()]
   [bool]$removePreviousPermisions = $false

   )
	Process {
		$returnVal = $false
		try {
			$acl =( Get-Item $path).GetAccessControl('Access')
			
			$aclPermision = New-CANewAccessControlObject -path $path -identity $identity -rights $rights
			$acl.AddAccessRule($aclPermision)

			$acl = Set-Acl -Path $path -AclObject $acl -Passthru
		} Catch {
			Write-LogMessage -Type "Error" -Msg "Failed to set new permissions: '$rights' on path: '$path' to user\group: '$identity' Error: $(Join-ExceptionMessage $_.Exception)" 
		}
	}
	End{
   }
}

function SetAclPermissions($username, $path, $permissions, $allowOrDeny){
	
	$aclFromPath = Get-Acl $path
	
	$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($username,$permissions,"ContainerInherit, ObjectInherit","None",$allowOrDeny)
	 
	 $aclFromPath.SetAccessRule($AccessRule)
	 
	 Set-Acl -Path $path -AclObject $aclFromPath
}


function Add-CAUserRight {
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $userName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $userRight
    )
    Process {
        try {
            $ntprincipal = new-object System.Security.Principal.NTAccount "$userName"
            $userSid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
            $userSidstr = $userSid.Value.ToString()

            if ([string]::IsNullOrEmpty($userSidstr)) {
                Write-LogMessage -Type "Error" -Msg "User $userName not found!"
            }

            $tempPath = [System.IO.Path]::GetTempPath()
            $exportPath = Join-Path -Path $tempPath -ChildPath "export.inf"
            secedit.exe /export /cfg "$exportPath" >$null 2>&1

            $currentRightKeyValue = (Select-String $exportPath -Pattern "$userRight").Line
            $splitedKeyValue = $currentRightKeyValue.split("=", [System.StringSplitOptions]::RemoveEmptyEntries)
            $currentSidsValue = $splitedKeyValue[1].Trim()

            if ($currentSidsValue -notlike "*$userSidstr*") {
                $newSidsValue = if ([string]::IsNullOrEmpty($currentSidsValue)) { "*$userSidstr" } else { "*$userSidstr,$currentSidsValue" }

                $importPath = Join-Path -Path $tempPath -ChildPath "import.inf"
                $importFileContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$userRight = $newSidsValue
"@
                Set-Content -Path $importPath -Value $importFileContent -Encoding Unicode -Force
                secedit.exe /configure /db secedit.sdb /cfg "$importPath" /areas USER_RIGHTS >$null 2>&1
            }

            Remove-Item -Path $importPath -Force
            Remove-Item -Path $exportPath -Force
        } catch {
            Write-LogMessage -Type "Error" -Msg "Failed to add $userRight user right for user $userName. Error: $_"
        }
    }
}

Function CheckIfNewDiscoveryEnabled(){
    Try{
        Write-LogMessage "Retrieving tenant details"
        $GetTenantSettingsInvoke = Invoke-RestMethod -Uri "$URL_PVWAAPI/settings/features" -Method Get -ContentType "application/json" -TimeoutSec 10 -Headers $pvwaLogonHeader -ErrorVariable pvwaERR
    }Catch{
        Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
    }
    Return $GetTenantSettingsInvoke.DisabledClassicDiscovery
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
        [string]$AdminUser,
		[Parameter(Mandatory = $False)]
		[ValidateSet("CPM","PSM")]
		[string]$ComponentType
    )
	
if($ComponentType -eq "CPM"){
	$apikeyFileName = "apikey.ini"
}Else{
	$apikeyFileName = "apigw.cred"
}

Add-Type -AssemblyName System.Windows.Forms
$wshell = New-Object -ComObject wscript.shell
$ApiLogs = "$pathApiKey`Vault\Logs\ApiKeyManager.log"

#Purge logs before execution
Remove-Item $ApiLogs -Force -ErrorAction SilentlyContinue

Write-LogMessage -type Info -MSG "Resetting ApiKey, this can take a few secs..."
Write-LogMessage -type Info -MSG "Testing if SendWait function will work..."
$dummyString = "Test"
$teststring = $null
$specialchars = '!@#$%^&*()'',./\`~[]":?<>+|'.ToCharArray()
[string]$simplePw = ($Credentials.GetNetworkCredential().password)

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
    & "$pathApikey\Vault\ApiKeyManager.exe" add -f "$pathApikey`Vault\$apikeyFileName" -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
}
Else{
Write-LogMessage -type Warning -Msg "Error Powershell's SendWait command doesn't work, probably because you have Endpoint agent blocking this action."
Write-LogMessage -type Warning -Msg "You will have to input your administrative account manually (the same account pw you input at the start of the script)."
& "$pathApikey\Vault\ApiKeyManager.exe" revoke -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
& "$pathApikey\Vault\ApiKeyManager.exe" add -f "$pathApikey`Vault\$apikeyFileName" -t $apiUser -u $AdminUser -a "$URL_PVWAAPI/"
}

if(gc $ApiLogs | Select-String "ERROR"){
Write-LogMessage -type Warning -MSG "Couldn't reset API key, check for errors in logfile: $ApiLogs"
}

$simplePw = $null
}

# -----------------------------------
# Script Begins Here
Write-LogMessage -type Info -MSG "Starting Create CredFile helper script" -Header
$gitHubLatestVersionParameters = @{
    currentVersion = $ScriptVersion;
    repositoryName = "pCloudServices/CreateCredHelper";
    scriptVersionFileName = "CreateCredFile-Helper.ps1";
    sourceFolderPath = $PSScriptRoot;
}

If(! $SkipVersionCheck)
{
	try{
        Write-LogMessage -type Info -Msg "Current script version $ScriptVersion"
        $isLatestVersion = $(Test-GitHubLatestVersion @gitHubLatestVersionParameters)
		If($isLatestVersion -eq $false)
		{
			$scriptPathAndArgs = "`& `"$PSScriptRoot\CreateCredFile-Helper.ps1`" -SkipVersionCheck"
			Write-LogMessage -type Info -Msg "Finished Updating, relaunching the script"
			Invoke-Expression $scriptPathAndArgs
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
    
    # skip TLS checks
    if(-not($skipTLS)){enforceTLS}
    # ignore cert issues
    if(-not($SkipCertVerification)){IgnoreCert}

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
            if ($typeChosen.Name -eq "CPM" -and $typeChosen.Version -ge [version]"14.2")
            {
                $typeChosen.InitPVWAURL()
                Invoke-Logon
                Foreach($svc in $typeChosen.ServiceName)
                {
                    Stop-CYBRService -ServiceName $svc
                }
                $resolvedComponentUser = Resolve-ComponentUserForCredFile -Component $typeChosen -CredFile $typeChosen.ComponentUser[0]
                $global:apiKeyUsername = $resolvedComponentUser
                $global:apiKeyPath = $typeChosen.Path
                Write-LogMessage -Type Info -MSG "CPM version $($typeChosen.Version) detected, using SyncCompUsers.exe to update CPM credentials instead of the legacy CreateCredFile.exe flow."
            }
            else
            {
                Invoke-ResetCredFile -Component $typeChosen
            }
            switch ($typeChosen.Name)
            {
                "CPM"
                {
                    $PluginManagerUser = "PluginManagerUser"
                    $cpmPath = $typeChosen.Path
                    if($typeChosen.Version -ge [version]"14.2"){
                        if(Test-Path $CPMnewSyncToolFolder){
                            ResetCPMUserandAPIkeyNewMethdod -cpmPath $cpmPath -credential $Credentials -apiUser $apiKeyUsername
                            Foreach($svc in $typeChosen.ServiceName)
                            {
                                if (-not($svc -eq "CyberArk Central Policy Manager Scanner")){
                                    Start-CYBRService -ServiceName $svc
                                }
                            }
                        }Else{
                            Throw "Couldn't find folder '$CPMnewSyncToolFolder'. Make sure you downloaded the latest tool package."
                        }
                        Try{Invoke-Logoff}Catch{}
                        Invoke-Logon
                    }
                    Write-LogMessage -type Info -MSG "Syncing $PluginManagerUser"
                    if ($typeChosen.Version -ge [version]"13.1")
                    {   
                        # Sync PluginManagerUser
                        # Get account details
                        $GetAccountResponse = Get-Account -AccountName "$PluginManagerUser" -URLAPI $URL_PVWAAPI -logonheader $pvwaLogonHeader -SafeName "$($apiKeyUsername)_Accounts" -limitPage 0
                        if($GetAccountResponse)
                        {
                            # Get account password using acc details
                            $GetAccPassword = Get-AccountPassword -AccountID $($GetAccountResponse.value.id) -URLAPI $URL_PVWAAPI -logonheader $pvwaLogonHeader
                            # If we get pw, perform an action to verify the windows user pw is correct
                            if($GetAccPassword){
                                $securePassword = ConvertTo-SecureString $GetAccPassword -AsPlainText -Force
                                Write-LogMessage -type Info -MSG "Successfully retrieved password, proceeding syncing locally."
                                # if local user doesn't exist, let's create it so we can reset pw.
                                if(-not(Get-LocalUser $PluginManagerUser -ErrorAction SilentlyContinue)){
                                    Write-LogMessage -type Warning -MSG "User '$PluginManagerUser does not exist, let's try to create it."
                                    
                                    Add-CALocalUser -userName $PluginManagerUser -userPassword $securePassword -userDescription "CyberArk Plugin Manager User used by CyberArk Password Manager service"
                                    # Retrieve PasswordManagerUser SID
                                    $ntprincipal = new-object System.Security.Principal.NTAccount "$PluginManagerUser"
                                    $userSid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
                                    $userSidstr = $userSid.Value.ToString()
                                    # Retrieve PasswordManagerUser registry path
                                    [string]$DnsHost = $env:COMPUTERNAME.Trim()
                                    $userREGPaths = @("registry::HKEY_USERS\$userSidstr\Software","registry::HKEY_USERS\$userSidstr")
                                    # Grant regsitry permissions
                                    Write-LogMessage -type Info -MSG "Granting registry permissions."
                                    foreach ($userREGPath in $userREGPaths){ 
                                        Set-CAPermissions $userREGPath "$DnsHost\$PluginManagerUser" "FullControl"
                                    }
                                    Write-LogMessage -type Info -MSG "Granting folder permissions."
                                    SetAclPermissions $PluginManagerUser ($env:USERPROFILE + "\..\" + "$PluginManagerUser") "FullControl" "Allow"
                                    SetAclPermissions $PluginManagerUser ($cpmPath) "ReadAndExecute" "Allow"	 
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "Scanner") "ReadAndExecute" "Deny"
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "Logs") "Modify" "Allow"
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "tmp") "FullControl" "Allow"
                                    SetAclPermissions $PluginManagerUser ($cpmPath + "\" + "bin") "ReadAndExecute" "Allow"
                                    Write-LogMessage -type Info -MSG "Adding User to 'Allow log on locally' policy."
                                    Add-CAUserRight $PluginManagerUser "SeInteractiveLogonRight"
                                }
                                

                                # Check password is in sync by running generic powershell command
                                $success = $false
                                $LocalUserCreds = New-Object System.Management.Automation.PSCredential ($PluginManagerUser, $securePassword)
                                Write-LogMessage -type Info -MSG "Running test command using password from the vault with windows user '$PluginManagerUser'"
                                # Run generic command in AD
                                $validationResult = Test-Credential -credential $LocalUserCreds -context 'Machine'
                                if ($validationResult){
                                    Write-LogMessage -type Success -MSG "Account: $PluginManagerUser is synced!"
                                }Else{                                
                                    Write-LogMessage -type Warning -MSG "Account: $PluginManagerUser is out of sync!"
                                    $SyncAccountDecission = Get-Choice -Title "Would you like the script to attempt to sync the accounts?" -Options "Yes (Recommended)", "No" -DefaultChoice 1
                                    if ($SyncAccountDecission -eq "No") {
                                        Write-LogMessage -Type info -MSG "Selected not to sync user $PluginManagerUser ."
                                    }Else{
                                        # Sync local user with password from vault
                                        Reset-LocalUserPassword -Credential $LocalUserCreds
                                    }
                                }
                            }
                            Else
                            {
                                Write-LogMessage -type Error -MSG "Was unable to retrieve account password: '$($PluginManagerUser)' You will have to do this manually."
                            }
                        }
                        Else
                        {
                            Write-LogMessage -type Error -MSG "Was unable to retrieve account: '$($PluginManagerUser)' You will have to do this manually."
                        }
                    }Else{
                        Write-LogMessage -type Warning -MSG "Old CPM version detected, can't perform $PluginManagerUser Sync action, do it manually by contacting CyberArk Support if the user is out of sync."
                    }
                        # Skip CPM Scanner service if new discovery is enabled, False means we need to use old scanner and reset apikey.
                        $discoverySetting = CheckIfNewDiscoveryEnabled
                        if ($discoverySetting -eq $false -or $discoverySetting -eq $null){
                            # Reset APIKey
                            $decisionAPIKey = Get-Choice -Title "(Optional) Would you like to also reset CPM Scanner APIKey?" -Options "Yes", "No" -DefaultChoice 1
                            if ($decisionAPIKey -eq "No") {
                                Write-LogMessage -Type info -MSG "Selected not to run CPM Scanner APIKey reset."
                                # Scanner service
                                Start-CYBRService -ServiceName $typeChosen.ServiceName[1]
                            } else {
                                # in 14.2 CPM deprecated apikeymanger tool and we need to use the new tool
                                if($typeChosen.Version -ge [version]"14.2"){
                                    Write-LogMessage -type Info -MSG "CPM component credentials were already updated using SyncCompUsers.exe earlier in the flow."
                                }
                                Else
                                {
                                    Invoke-ResetAPIKey -pathApikey $apiKeyPath -apiUser $apiKeyUsername -AdminUser $Credentials.UserName -ComponentType CPM
                                }
                                # finally Scanner service
                                Start-CYBRService -ServiceName $typeChosen.ServiceName[1]
                                $Credentials = $null
                            }
                        }Else{
                            Write-LogMessage -type Success -MSG "Skipping $($typeChosen.ServiceName[1]) since New Discovery service is enabled on tenant."
                        }
                }
				"PSM"
				{
						$decisionAPIKey = Get-Choice -Title "(Optional )Would you like to also reset PSM APIKey?" -Options "Yes", "No" -DefaultChoice 2
                        if ($decisionAPIKey -eq "No") {
                            Write-LogMessage -Type info -MSG "Selected not to run PSM Scanner APIKey reset."
                        } else {
							Stop-CYBRService -ServiceName $typeChosen.ServiceName
                            Invoke-ResetAPIKey -pathApikey $apiKeyPath -apiUser $apiKeyUsername -AdminUser $Credentials.UserName -ComponentType PSM
                            Start-CYBRService -ServiceName $typeChosen.ServiceName
                            $Credentials = $null
                        }
				}
            }
			# TODO maybe add logs check here instead?
			Test-SystemLogs -ComponentID $typeChosen.Name -LogPath $typeChosen.serviceLogs[0] | Out-Null
        }
    }
    else {
        Write-LogMessage -Type Warning -MSG "There were no CyberArk components found on this machine"
    }
} catch {
    Write-LogMessage -type Error -Msg "There was an error running the script. Error $(Join-ExceptionMessage $_.Exception)"
}
Finally{
    Try{Invoke-Logoff}Catch{}
    $Credentials = $null
}
# Script ended
Write-LogMessage -type Info -MSG "Create CredFile helper script ended" -Footer
return

# SIG # Begin signature block
# MIIpLQYJKoZIhvcNAQcCoIIpHjCCKRoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCiAUPjqeAf/zWO
# EMcWvfjfoI1qkrwCw+MGChb1LYc1AaCCDq8wggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB78wggWnoAMCAQICDFvWkQMw/ZfAZpUM
# wDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjYwMzAyMjE1MjMzWhcNMjcwMjI3MTM0MDU2WjCC
# AQQxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRIwEAYDVQQFEwk1MTIy
# OTE2NDIxEzARBgsrBgEEAYI3PAIBAxMCSUwxCzAJBgNVBAYTAklMMRkwFwYDVQQI
# ExBDZW50cmFsIERpc3RyaWN0MRQwEgYDVQQHEwtQZXRhaCBUaWt2YTEXMBUGA1UE
# CRMOOSBIYXBzYWdvdCBTdC4xHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0
# ZC4xHzAdBgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xITAfBgkqhkiG9w0B
# CQEWEmFkbWluQGN5YmVyYXJrLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAKtAr5PeV7TdJZDWUNp8j60tepBmgC2+9Dw8tUh+RsLhqaSNi0dUc7i9
# yznveSdnfE4l2U8ZXyEILjQsSJw3SaPaXMSOzR4wVnuTc1nTzKBOS3oa6Yil7rlu
# gNXVj8dmEEehcPuAkF4ciqt6YChi5a6DD/r8GYuHv+/75XDZCD1nTPesDLIN+RAU
# aqHWLF0XRDXwF/JgB6W+lzIuYeiXdM/jPxZqvg1d7WKZQCy0maucWE/n4N4/8nPT
# qLm3y8jhUdP6YGUlyJLbC4fxbVW1KrhDMY1DOOtItuBiOeBVAvVctbw/kAvEc32Y
# Iz3qIWTmcR0VzVVV6IlNWOrMqJZEvtHlqRVkekLJXB5pVw6b3PuelU92cb+VtUnB
# hewMxSkPj8094wN7urFk7wXxVtNVTYtkmT5ThcphO5Sha1bCfTgymePAfUJW2p2o
# FdNBDeMoSmVlTDDlffRpyMzFZpHpc6v0HzeLmkEcZk+HRf5dgeRMQZWt/Mgsizwe
# w0RuaCeQlphX7RgBRkC9rT57RCcBMtW3blk4Vz6qncCKCLBCJK1CIrC2frGX7vqt
# In+0zR1K0ec8tTH5im5QEE72MuMV+/4KbP+ISojaQ8JFZvqESxyAUbjpQcE2pfzv
# fwKiSXTyOCv9buuHDViUhoSc9oEKA3iuhc8Yz21F4CO0MTj014+FAgMBAAGjggHV
# MIIB0TAOBgNVHQ8BAf8EBAMCB4AwgZ8GCCsGAQUFBwEBBIGSMIGPMEwGCCsGAQUF
# BzAChkBodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2djY3I0
# NWV2Y29kZXNpZ25jYTIwMjAuY3J0MD8GCCsGAQUFBzABhjNodHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9nc2djY3I0NWV2Y29kZXNpZ25jYTIwMjAwVQYDVR0gBE4w
# TDBBBgkrBgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFs
# c2lnbi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwCQYDVR0TBAIwADBHBgNVHR8E
# QDA+MDygOqA4hjZodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZj
# b2Rlc2lnbmNhMjAyMC5jcmwwHQYDVR0RBBYwFIESYWRtaW5AY3liZXJhcmsuY29t
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7
# VxwDkjYRMB0GA1UdDgQWBBR/nObXnnoINvefWdWmW4iZSqmPAjANBgkqhkiG9w0B
# AQsFAAOCAgEAvpUZ9sMYv3kb7+v5CzJoUgOAtOF21kKgzqrgRmwH/xyuXkhs+tY9
# LCE3ldhZmAJIfgBKZuKUQL5eFmLHltBevBKfgmfaT6uoG0sJ3QyNu46m2hMr/gvm
# Kms2zfFGOZxG8wHeZUQ1v8imN80Frvvy1DIdA1QOW4hIJvt1GbCaS6TTC3eO9/fO
# r22hHk0IBt+LtmSeA/rdFsnwT4Y4SY4mebZZePHH9c+KreM64DAP61rLodKQCw14
# jbPTlQRSelbJpb+Vmo7q1sieuCY5US2KsXG/4P/ENEJFnwH+ib671IjN7L4AISzt
# BoKY81CNMBSziqMpdCwrAiXBQhBHdKUG28MhrxS1gB564h+fo9tMrV5pe6Jp60Sa
# Wn5aQzu/nWR6z+gUR9mk5SdjBow+Liykxd/2o5wT8AmJ6XE/vGd7lK8MnuoTeJ65
# WQOsMd7MyB4tP3CV9/r+JESfPExxK3ybfWp1cAigtzpGII2fUM0sx43Wd7w0Ugfp
# OjmGOUKpshp6zJAqG+NNbupqk5vHAiddvHHRrZGLF7qbc0jcdQyxygyxQLe5Quu3
# M/bZ5+b4T+4xT/b0hmU4WmiHV8h3OF6U6OvIU2+gJ8NtRSkl+Jz/nhhU5hhNh2Ad
# TB108wYNMYET2xxoxtEPL5Sb0rX07I4lEGPpbwAcP1jds2+pgeB1pYcxghnUMIIZ
# 0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNh
# MTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0Eg
# MjAyMAIMW9aRAzD9l8BmlQzAMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIB
# DDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHtjH3zO8E0fKGdRT+sghvPN
# P/C8DKwkC2e+zTr2iRG/MA0GCSqGSIb3DQEBAQUABIICABk0fSsNMIKOcpdD1+f8
# q82WYSfjO1FjLXgnZC/cWnXGNje0F0Lj9HHGJRfrI/mYSzuQjAuduCQypplLuzaG
# tup/RUyyrr9s1C/vQ3P6LA9/zTQUfUWX/3phPAbWNcABEHtVDRn9Y+0javAT9AGK
# d8l/koWOwkyhncBOJef+0dmWut9AZoLeF2F8OIL5Dr778Rbn+B41UbKSAI+fLkb1
# mW364OXx1r8oYo9SMFdQyVSbdIxWmUjRAVb7YCRk4wMgry7zeVATtK9N9D3X0NUb
# HblXm9uiLK2PF8VbRA1mV7dHDoh3lElLls4PxC+hUHtj7YdHJIZywoxGCxIcf77X
# t4psauLGol5EAXIaj6qHTg1Y/759T/1gDScvukRpR4cviRKeNJguNI0fRhzIIshW
# XuBZaYP2O2JzpxlrffnDeJnyvgAnG/mlHAmkc8HM3vaxp/KGEP7p4LILzwBJgypK
# jROLeNwg3/k6ijYRrx4+TP0Wk8NNSX0cFpQ3JQCtfbWt5/fJR/3kGRNfgacbSAyT
# KzUVdxEwn054QP5Fulw8t8jO7ItZHZUNaNSIwPMJhBKwapEuyxSb8YBrAx7j99rD
# I3KlvEnnCLJhUykcpyr8mlkJGdWU88Tbm+ppc1MI+Vo5Dw/1B3MeXAQk+YtmBK/r
# dq0tpe+xJfr2lWhRKcGCM8jkoYIWuzCCFrcGCisGAQQBgjcDAwExghanMIIWowYJ
# KoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqGSIb3DQEJ
# EAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQCAQUABCAy
# AKaLglchb1tuY11x2w5Ctfs6ZyIxLLBMa3O0xIR/PwIUEHdHCughQYQ//BUCN41V
# bR8wYKcYDzIwMjYwNDA3MjAwNjA4WjADAgEBoFikVjBUMQswCQYDVQQGEwJCRTEZ
# MBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBU
# U0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEACyAFs5QH
# Yts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQxMjEwMDAw
# MDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEq
# MCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2MIIBojAN
# BgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aqCj7V8qyo
# p0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy3MNEj1qE
# +ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6efi2BySHX
# shZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1NWhxP/HsN
# um67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04DuKbDwRd6n
# rm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFHaS0x3SgF
# akvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+2Klndcz/
# 9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCzk6sEBLRV
# PEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAOBgNVHQ8B
# Af8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFIBDTPy6
# bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIB
# HjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEF
# BQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4
# NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2Nh
# Y2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkz
# pPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2ln
# bi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwFAAOCAgEA
# t6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMIrN5VdX8K
# Gl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mHolGLBwyD
# m74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/MhNUaKg34y
# aJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU15YTvG+X
# xt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9LQ1ILOpq
# G/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc1gRgPsDs
# U9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiGkyw3EKNi
# yHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbAWQ6NNuq9
# ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJD7xe/rqU
# LwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh62QVAl/ga
# dTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaADAgECAg0B
# 7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNp
# Z24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH
# bG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEds
# b2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5
# I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M
# 95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc
# 8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGS
# O/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF
# +lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6P
# SXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcm
# x/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF
# 5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJM
# YDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPY
# dgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+
# EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQY
# MBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEF
# BQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8E
# LzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3Js
# MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5n
# bG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI
# 2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99ak
# DY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLI
# t59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SR
# GK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8
# u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZr
# GM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDF
# UVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpI
# J3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxy
# YUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+Pvafnzka
# rqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd9
# 8rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsD
# gzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWdu
# IFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv
# YmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMaw
# iGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjI
# ElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0y
# BqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3
# YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHN
# V5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTah
# b1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV
# 2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9
# ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmF
# zzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT
# 6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEw
# DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOT
# E+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jW
# ZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMT
# VlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgH
# M3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3b
# mZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9Bx
# gXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1e
# bcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRg
# emSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2Zla
# tJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQl
# p7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l3
# 1VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MF
# WsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENB
# IC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUDBAIBoIIB
# LTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDAL
# BglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEINz3CFMD
# VSxopNa1T5o7A3RMM+9h9Bc3FQFKnuOglmXEMIGwBgsqhkiG9w0BCRACLzGBoDCB
# nTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0wczBfpF0w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAMvB+UidJDJuOL1X9Blsy
# EhZTn3sTM/4H00dWab0EksclNNn9WZRgBbBqNVzctVhKTHGMqNnp5pO5hP0KZXwM
# 6tKscyYXBHcRnz3Ji7ytuSRl1IQdZ64sz0C64sJcy3z4bPWzzZsk8rKBkomkWr5Z
# x+jLZCFyU2HjCT2SM/KWOBmQxYcbxKKjR7Yj/sLJmBdCc4LhfJAwrbz81BxZb/Jr
# /InpK/2qkwdPKT2AUxdxAUNLah5PLMLjzawdHwrY21/fxCKQ+DVkLvmgWNVsekia
# wJ6l5t7pLlDhdoFXk6yo9hqga4Pc0vpim6qff47N5QTvRtF6O9vmZT1cUETZV9wH
# nANCf3AUyeS3ZRWfbEZURP9eDDXUuYfBHD/cCBWcV9CNqZFG3158b/TG2Xct9ZiL
# HvM0AGtHi+F6c4w/sFirZlGXBvmawm0U8oqP6xms/fJ/b9VEpZdpOJgts/izPtUO
# kSTNm2EUj5qSxn4x8MySat4MtAmmky2xW7ufugKe9ZnW
# SIG # End signature block
