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
$global:CPMnewSyncToolFolder = "$PSScriptRoot\SyncCPMCompUsers_neededFrom14.2+"

# Script Version
$ScriptVersion = "3.8"

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
							$fileVersion = [version](Get-FileVersion "$pvwaPath\Services\CyberArkScheduledTasks.exe")
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
                            $myObject = New-Object PSObject -Property @{Name="PSM";DisplayName="CyberArk Privileged Session Manager (PSM)";
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
                        if (($GetPVWAStringURL -like "vault-*.cyberark.com") -or ($GetPVWAStringURL -like "*vault-*.cyberark.cloud")){
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
    if(-not($Credentials)){
        [PSCredential]$script:Credentials = $Host.UI.PromptForCredential($caption,$msg,"","")
    }
    try{
        # Login to PVWA
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
    
    Write-LogMessage -type Info -MSG "Input JSON file created/updated at $InputFile"
    

    function RunProcess {
        param (
            [Parameter(Mandatory=$true)]
            [string]$ProcessFullPath,
    
            [Parameter(Mandatory=$false)]
            [string[]]$Args
    
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
    
            [System.Environment]::SetEnvironmentVariable("VAULT_PASSWORD", $Credentials.GetNetworkCredential().Password)
    
    
            $process = (Start-Process $ProcessName "$processArgs" -WorkingDirectory $processPath -Wait -WindowStyle Hidden -PassThru)
            $processExitCode = $process.ExitCode.ToString()
            [bool]$isSuccess = $false
            if ($process.ExitCode -eq 0) {
                Write-LogMessage -type Success -MSG "Process $processName finished successfully"
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
    
        RunProcess -ProcessFullPath $ExecutableFullPath -Args $args
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
            Invoke-ResetCredFile -Component $typeChosen
            switch ($typeChosen.Name)
            {
                "CPM"
                {
                    $PluginManagerUser = "PluginManagerUser"
                    $cpmPath = $typeChosen.Path
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
                        # Reset APIKey
                        $decisionAPIKey = Get-Choice -Title "(Optional) Would you like to also reset CPM Scanner APIKey?" -Options "Yes", "No" -DefaultChoice 1
                        if ($decisionAPIKey -eq "No") {
                            Write-LogMessage -Type info -MSG "Selected not to run CPM Scanner APIKey reset."
                            # Scanner service
                            Start-CYBRService -ServiceName $typeChosen.ServiceName[1]
                        } else {
                            # in 14.2 CPM deprecated apikeymanger tool and we need to use the new tool
                            if($typeChosen.Version -ge [version]"14.2"){
                                $syncCompAPpPath = "SyncCPMCompUsers_neededFrom14.2+"
                                #check app exists
                                if(Test-Path ".\$syncCompAPpPath"){
                                    ResetCPMUserandAPIkeyNewMethdod -cpmPath $cpmPath -credential $Credentials -apiUser $apiKeyUsername
                                }Else{
                                    Write-LogMessage -type Error -MSG "Couldn't find folder $syncCompAPpPath make sure you download the latest zip from marketplace."
                                    Write-LogMessage -type Error -MSG "Skipping API Key reset..."
                                }
                            }
                            Else
                            {
                                Invoke-ResetAPIKey -pathApikey $apiKeyPath -apiUser $apiKeyUsername -AdminUser $Credentials.UserName -ComponentType CPM
                            }
                            # finally Scanner service
                            Start-CYBRService -ServiceName $typeChosen.ServiceName[1]
                            $Credentials = $null
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
###########

# SIG # Begin signature block
# MIIzKQYJKoZIhvcNAQcCoIIzGjCCMxYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB1VAnnFqDTBmKC
# akvxcZ9caEApPJOPrw9Wog2PxZa+GqCCGJkwggROMIIDNqADAgECAg0B7l8Wnf+X
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
# HvZ/UuJJjbkRcgyIRCYzZgFE3+QzDiHeYolIB9r1MIIHsTCCBZmgAwIBAgIMBmw4
# iuAOfBdrKw0JMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUg
# RVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yNTAxMjgxMDI4MzNaFw0yODAxMjkx
# MDI4MzNaMIH3MR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjESMBAGA1UE
# BRMJNTEyMjkxNjQyMRMwEQYLKwYBBAGCNzwCAQMTAklMMQswCQYDVQQGEwJJTDEQ
# MA4GA1UECBMHQ2VudHJhbDEUMBIGA1UEBxMLUGV0YWggVGlrdmExEzARBgNVBAkT
# CjkgSGFwc2Fnb3QxHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xHzAd
# BgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xITAfBgkqhkiG9w0BCQEWEmFk
# bWluQGN5YmVyYXJrLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANZQPlxrcfMjyi+hhEn41HogbUr17cJB+2rbTOBphAPzZEySpd+GObt2pAyYbXTb
# 1XGHRomYxq/fTVcDWn6ESHKqIpTUnTsai2FakMr4OINfey2c0Lw81SCwedG6ind+
# QxszJ3c1iAoyuO8fbNAJJQHKTNAdTCADAHrfHvv8fuF8iw8vZCP5E6JFdcvaNUL9
# 9lecTTlIuXMyfLoO/9Q6geZ30UeSibynHoZbGzzK20pxL9VM5LA9YiGtA+bfdRGe
# hlqhPD4KgBRkc9bogTxA78QaiBUEnYM1vMmKc86MjXSS6R+z5mFAdhcs5C6cqWdO
# wo5jVFXpwxQh0jNTalt/kkwTjlIeO3+fdDDYLmbmH3nIsMutaHyXPogVp7upktz9
# WeS9r0ZpqKw7viVe/CWS9Df8/ceZD9zBkIbTrYGFU02hDaWaN1pFs6V21iaiTaZX
# pnnpEbtgoy8rptlFFIf0GQBDD0mTBDm7lZ8rDfN7IECcahCN4dMfnFO/QFpxAILa
# ekomXUmtkH3WBaQl4hraHja+fCi4ZtKhYYTZWdakH6bvdkENywuze/liwv2OVdZ4
# qddJpbvblqa9jqnV8RhugofYVEBq6yyd6OgJosdFPIZN7upzrCmHJTiTDtBNQJ2z
# m7LXrryUF9yTyjeUjLbUfTKbpj4UzM3jcKu1J5jDL5zFAgMBAAGjggHVMIIB0TAO
# BgNVHQ8BAf8EBAMCB4AwgZ8GCCsGAQUFBwEBBIGSMIGPMEwGCCsGAQUFBzAChkBo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc2djY3I0NWV2Y29k
# ZXNpZ25jYTIwMjAuY3J0MD8GCCsGAQUFBzABhjNodHRwOi8vb2NzcC5nbG9iYWxz
# aWduLmNvbS9nc2djY3I0NWV2Y29kZXNpZ25jYTIwMjAwVQYDVR0gBE4wTDBBBgkr
# BgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j
# b20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwCQYDVR0TBAIwADBHBgNVHR8EQDA+MDyg
# OqA4hjZodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2ln
# bmNhMjAyMC5jcmwwHQYDVR0RBBYwFIESYWRtaW5AY3liZXJhcmsuY29tMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7VxwDkjYR
# MB0GA1UdDgQWBBQewhxJyrlxdN3533DHK3x6hrz7uzANBgkqhkiG9w0BAQsFAAOC
# AgEAWgNDad105JaVijYhNrwnSPmm1mIhDpSvPDvIR4pENU9IdPcI8rxXRmJ083JM
# vIx5p7LvuBOTkyaNgZOjmkypMNM4NtMtHHdXAiWb6T+Udv4w0lcgUBWapeRxO7X5
# ok+E9lrVeSiiSrM/6TDF3xkAwcR5CzYjEYsgYa0H+hBXl9+oXe2QYFuArlQ0OfTv
# nXr2iFlvl0AKR7fRY0qBBGoKUATjGiYUFcigc9PyW2vml1BMxXx65jkKdoPIMZSJ
# Ka7xkExONB+t3uJc8yI+n2x24k1bjl8mJdnEkryUATe58vLxfYa93mLFC7VLCTND
# cJjFBvdL86F1HyveXhHX5XMlS/HPcnRk6VV8+zkr72fGP18cxl1nOAftgjOxh0mD
# Y6l9UMkOle1gSlf/S15z6VlRx+TkE/ZeL2n/tw4zHqWaNatHy+Zs2BIzaMdzP/u4
# tYTOuhQfXYnP5zrGw5ldYkIAQawVZwcODVO+FBb8/F3uTBbiMqCaOxy8RGLTqJlI
# bk+fBnkgtYyiIglUE10Y/FwI4qMgG2iZh97WsISLblu4Lfz9t7/bo54Y4bGqOdnW
# rz6e4hDhlkozop7MHG35nqHRN5Qx4iUDxvyDJLpZXG0kes+Cx+zkqhGvz9ST0bB6
# WH5RcnIk2Rog6Rr/bs0O1ZMS5DZy6vm1RB5fAZfAZ451uRwxghnmMIIZ4gIBATBs
# MFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYD
# VQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMAIM
# Bmw4iuAOfBdrKw0JMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILorrkgNsEV5MZynysmv/m34Nz0pskeH
# 4odNmTXenmjeMA0GCSqGSIb3DQEBAQUABIICAHsgvCQ/wzmD6GZiQH3dQgB7y4Xz
# Pq2ITK5mOQh3Qm6hkYglG+reIuWrA55EEoPlgf9hEw6vxeq2ugYKM5n/ADhIq7L7
# r3mANFgsT6ElOfewrjNk8u86jVzGk8zpap8xukEn/5+swO8bLnVY/pfEaX3A1oKx
# NF3zGSqTS3S6cpa20KksCOyyLPaz4CXLKMj6QelMUpvtY5/W4f0k98n0yysQBhh0
# nnSshC3YvirSOlvJYsNc0PxGaMF2R76P40pX5Smk0SsnX4Swh8/8YSSLj5+tWNO7
# VGjZAo+L2rDAFzIfI9/Gc+jDhZ+CUWfsXFzK3V8+FNzUuGrv7Dk69jqDQjGOyWYO
# cLjPPcOIkXdKHhWFD1YtJfj/vUws3T/PeG3bdJtLXPNcQbrINY+roI/Xcsu76ZWu
# ps7Cn/FP/xOjglrKYnV8Yw2XJmkgpf4NoBDrp3/coOmp9cBqct6AlU6cbvf6K76n
# 3/sTXt5Gz5aN03r3Y0gzWJ/V1Xzv7jEWiLfh+WJiaksppmKcLdjubOewZdfU4JN+
# vDgfnN804OBYhGUTLWWNQSuSEWQuXRSQ7d8aFNVpkrVwyZE8uWqXFcSCOQS+pU4+
# iFk9f3dVNzwN4QbFFNisdu/dSroGUp+K9AzV23MDu+qAWmsREX5CtbQfyEW2A+32
# B2ZPB++WC/MISSfCoYIWzTCCFskGCisGAQQBgjcDAwExgha5MIIWtQYJKoZIhvcN
# AQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEwgegGCyqGSIb3DQEJEAEEoIHY
# BIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQCAQUABCBKUYtBPRm2
# 53HjWwez2tuxDUp91t/XMdTL2QZzuB3vpwIUb/z5FyRu+6G5OuyLg3ihvK/zd8gY
# DzIwMjUwMjA1MTYxNDA5WjADAgEBoGGkXzBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCCBmwwggRUoAMCAQICEAGb6t7I
# TWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCQkUxGTAXBgNV
# BAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0
# YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMxMTA3MTcxMzQwWhcNMzQxMjA5
# MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1z
# YTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0g
# MjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA6oQ3UGg8lYW1
# SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5gN0lzm7iYsxTg74yTcCC19SvX
# ZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4LjzfWR1DJpC5cad4tiHc4vvoI2X
# fhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+2qlWfn+cXTY9YzQhS8jSoxMa
# Pi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQHnssW7AE9L1yY86wMSEBAmpy
# siIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMubg4htINIgzoGraiJLeZBC5oJC
# rwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapUl05tw3rdhobUOzdHOOgDPDG/
# TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAdM9DzlR347XG0C0HVZHmivGAu
# w3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8iL8nLMP5IKLBAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/kX7LlFRq3lxFALgBBvsU/JKAb
# RwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e0SQdI8svHKsnerOpxS8M5OWQ
# 8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/RnOhDTfqD4f/E4D7+3lffBmvz
# agaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5BqiEIIHMjvKnr/dOXXUvItUP35Q
# lTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDzK3kPsUusw6PZo9wsnCsjlvZ6
# KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q3+7OYSHTtZVUSTshUT2hI4WS
# wlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7OrTUNMxi1jVhjqZQ+4h0Htcx
# NSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0kIGDyE+Gyt1Kl9t+kFAloWHs
# hps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR/xeKriMJKyGuYu737jfnsMmz
# Fe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ9/TVjSGvY7br9OIXRp+31wdu
# ap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ4qq/TVkAF55gZzpHEqAwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIAy8ldHcNjv2Ny4hAJlGMXDkj+aYvO2ROLRmk2Q3oEuRMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe4U9su3aCN6VF0BBb8EURveJf
# gqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAEggGAWAFJ
# rpZP6PxDxVY7JPXlje5q/5NnkyXQKkTOiwGbi7PfGm6JkC0L/xprPE6kGYgawK6+
# ugcHT/Z31W88XjOKrEmbiL1CnpAZS8Eq0gn6Cn1VX54wC1B5uhPdB6ueRt839Ru7
# GqmVLddv1R0xS7aRtqlMBDqm6RjimmUpTDnkyLjnWRynRXBv/aSrc+kO42RT8cNT
# I8T99zxIrXIQ2cLwLIsV8Oz0laUZ5AmR+bRG0wjieTu31qjWG/LXR1SxOka1yiSh
# rsaOGo5tyUZLNs4PT0a1nO7OWlt6sCpgq73JNmwTG+/6gi5tHhog5qpg9YxsA6/K
# wwr1HGEh82/NskoYKGwwfn17zEeGrLQOl9ZYnv2TgUioUywPjwQHqjiezcJCymOD
# DfR8Zr8T+pwlWTiDEoyjVjJ5gaomgATXRg1fSiMynZnvEY3WsOksFqM4xGIeu2WI
# 8zxFbbmwjnl9U+XjD5TNiPEvVb4y9G9KnCvSVvdN61tf9alqo9gJ60UuAIKJ
# SIG # End signature block
