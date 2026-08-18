#!/opt/freeware/bin/bash


PATH=/opt/freeware/bin:/usr/bin:/bin:$PATH
export PATH

check_prerequisites() {
    echo "***** Checking script prerequisites..."

    if [ -z "$BASH_VERSION" ]; then
        echo "ERROR: This script must be executed with Bash."
        exit 1
    fi

    bash_major_version="${BASH_VERSINFO[0]}"

    if [ "$bash_major_version" -lt 4 ]; then
        echo "ERROR: Bash 4.x or newer is required."
        echo "Detected Bash version: $BASH_VERSION"
        exit 1
    fi

    echo "***** Bash detected: $BASH_VERSION"

    grep_path="$(command -v grep 2>/dev/null)"

    if [ -z "$grep_path" ]; then
        echo "ERROR: grep was not found."
        exit 1
    fi

    echo "***** grep detected: $grep_path"

    if ! echo "Username=testuser" | grep -oP '(?<=Username=).*' >/dev/null 2>&1; then
        echo "ERROR: The detected grep does not support GNU grep -P/-o functionality."
        echo "Detected grep: $grep_path"
        echo ""
        echo "Install GNU grep from the AIX Toolbox and ensure:"
        echo "  /opt/freeware/bin"
        echo "appears before /usr/bin in PATH."
        exit 1
    fi

    echo "***** GNU grep PCRE support detected."

    curl_path="$(command -v curl 2>/dev/null)"

    if [ -z "$curl_path" ]; then
        echo "ERROR: curl was not found."
        exit 1
    fi

    echo "***** curl detected: $curl_path"

    if ! curl --version >/dev/null 2>&1; then
        echo "ERROR: curl exists but could not be executed."
        exit 1
    fi

    if [ ! -r /dev/urandom ]; then
        echo "ERROR: /dev/urandom is not available or cannot be read."
        exit 1
    fi

    echo "***** /dev/urandom available."

    for cmd in awk sed cut tr head sort wc ping; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "ERROR: Required command '$cmd' was not found."
            exit 1
        fi
    done

    echo "***** Standard utility checks passed."

    if [ "$(uname -s)" = "AIX" ]; then
        for cmd in stopsrc startsrc lssrc; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                echo "ERROR: AIX SRC command '$cmd' was not found."
                exit 1
            fi
        done

        echo "***** AIX SRC commands detected."
    fi

    echo "***** All prerequisite checks passed."
    echo ""
}

check_prerequisites

###########################################################################
#
# NAME: CyberArk Privilege Cloud CreateCredFile-Helper Linux Edition
#
# AUTHOR:  Mike Brook <mike.brook@cyberark.com>
#
# COMMENT:
# This tool will help you reset the applicative credentials via API and verify status against Privilege Cloud backend.
#
###########################################################################

#colors
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'
YELLOW='\033[0;33m'

# Default pw complexity policy, this controls how pw is generated (passparms.ini in the vault).
MinAlphabetic=1
MinNumeric=1
MinPunctuation=0
MinLength=20
MustMixCase="Yes"
MinUnique=4
MaxRepeatingCharacters=3

# Version
scriptVersion="5.2"               

reset_local_only=0
selected_component=""
component_provided=0
offline_cred_password_arg=""
offline_cred_password=""

#Functions

# PVWA Calls
pvwaLogin() {
    rest=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w " %{http_code}" "$pvwaURLAPI/Auth/CyberArk/Logon" \
        --header "Content-Type: application/json" \
        --data @<(
            cat <<EOF
{
	"username": "$adminuser",
	"password": "$adminpass",
	"concurrentSession": "false"
}
EOF
        ))
}

pvwaLogoff() {
    pvwaActivate=$(
        curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Auth/Logoff" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaGetUserId() {
# Call based on UserType (AppProvider, PSMServer etc')
local UserType="$1"
    pvwaGetUser=$(
        curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/Users?filter=componentUser\&search=$credUsername&UserType=$UserType" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaActivateUser() {
    pvwaActivate=$(
        curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Users/$userID/Activate" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaResetPW() {
    pvwaReset=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w "%{http_code}" "$pvwaURLAPI/Users/$userID/ResetPassword" \
        --header "Content-Type: application/json" \
        --header "Authorization: $pvwaHeaders" \
        --data @<(
            cat <<EOF
{
	"id": "$userID",
	"newPassword": "$randomPW",
	"concurrentSession": "false"
}
EOF
        ))
}

pvwaSystemHealthUser() {
    local app_name="$1"
    pvwaSystemHealth=$(
        curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/ComponentsMonitoringDetails/$app_name" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

# Function to check DNS resolution of a URL
check_dns_resolution() {
    local url="$1"
    local hostname
    hostname=$(echo "$url" | awk -F/ '{print $3}')
	# Remove .privilegecloud from the hostname
    hostname=${hostname//.privilegecloud/}
	
	echo "***** Checking we are able to resolve address $hostname"
    if ping -c 1 "$hostname" >/dev/null; then
        echo -e "***** ${GREEN}Hostname ($hostname) resolved successfully.${NC}"
    else
        echo -e "${RED}Can't resolve hostname ($hostname). Please check DNS settings. Aborting...${NC}"
        read -r -p "**** Proceed anyway?: [Y/N]: " response
		if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
			echo "**** Chosen YES"
			sleep 1
		else
			echo "**** Chosen NO, Exiting."
			sleep 1
			exit 1
		fi
    fi
}

creds() {
    read -p "Please Enter Privilege Cloud Install Username: " adminuser
    echo " "
    echo "***** Please Enter Privilege Cloud Install User Password and press ENTER *****"
    read -s adminpass
    if [ -z "$adminpass" ]; then
        echo "password is empty, rerun script"
        exit 1
    else
        adminpw="$(echo -e "${adminpass}" | tr -d '[:space:]')"
    fi
}

usage() {
    cat <<'EOF'
Usage:
  ./createCredFile-Helper.sh [--Component psmp|aim] [--ResetCredLocalOnly] [--OfflineCredPassword env:VAR_NAME]

Examples:
  ./createCredFile-Helper.sh --Component psmp
  read -s OFFLINE_CRED_PASSWORD; export OFFLINE_CRED_PASSWORD; ./createCredFile-Helper.sh --ResetCredLocalOnly --Component psmp --OfflineCredPassword env:OFFLINE_CRED_PASSWORD; unset OFFLINE_CRED_PASSWORD
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -ResetCredLocalOnly|--ResetCredLocalOnly)
                reset_local_only=1
                ;;
            -Component|--Component)
                shift
                if [[ -z "$1" ]]; then
                    echo "Missing value for --Component."
                    usage
                    exit 1
                fi
                selected_component="${1,,}"
                component_provided=1
                ;;
            -OfflineCredPassword|--OfflineCredPassword)
                shift
                if [[ -z "$1" ]]; then
                    echo "Missing value for --OfflineCredPassword."
                    usage
                    exit 1
                fi
                offline_cred_password_arg="$1"
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    if [[ $component_provided -eq 1 ]] && [[ "$selected_component" != "psmp" && "$selected_component" != "aim" ]]; then
        echo "Invalid component '$selected_component'. Allowed values on Linux are: psmp, aim."
        exit 1
    fi

    if [[ -n "$offline_cred_password_arg" && $reset_local_only -ne 1 ]]; then
        echo "--OfflineCredPassword can only be used together with --ResetCredLocalOnly."
        exit 1
    fi
}

resolve_offline_password() {
    if [[ -n "$offline_cred_password_arg" ]]; then
        case "$offline_cred_password_arg" in
            env:*)
                local var_name="${offline_cred_password_arg#env:}"
                if [[ -z "$var_name" || -z "${!var_name}" ]]; then
                    echo "The environment variable reference '$offline_cred_password_arg' is empty or not set."
                    echo "Example: read -s OFFLINE_CRED_PASSWORD; export OFFLINE_CRED_PASSWORD; ./createCredFile-Helper.sh --ResetCredLocalOnly --Component psmp --OfflineCredPassword env:OFFLINE_CRED_PASSWORD; unset OFFLINE_CRED_PASSWORD"
                    exit 1
                fi
                offline_cred_password="${!var_name}"
                ;;
            *)
                echo "Plain text passwords are not allowed with --OfflineCredPassword."
                echo "Use an environment variable reference instead."
                echo "Example: read -s OFFLINE_CRED_PASSWORD; export OFFLINE_CRED_PASSWORD; ./createCredFile-Helper.sh --ResetCredLocalOnly --Component psmp --OfflineCredPassword env:OFFLINE_CRED_PASSWORD; unset OFFLINE_CRED_PASSWORD"
                exit 1
                ;;
        esac
    else
        read -r -s -p "Enter the password that should be written into the local cred file(s): " offline_cred_password
        echo ""
        if [[ -z "$offline_cred_password" ]]; then
            echo "Password is empty, aborting."
            exit 1
        fi
    fi
}

restart_services() {
    local serviceName="$1"
    # Check if the operating system is AIX
    if [[ "$(uname -s)" == "AIX" ]]; then
        echo "***** Restarting $serviceName Service on AIX..."
        stopsrc -s ${serviceName}
        startsrc -s ${serviceName}
        lssrc -s ${serviceName}
    else
        echo "***** Reloading daemon service (systemctl daemon-reload)..."
        systemctl daemon-reload
		echo "***** Restarting $serviceName Service..."
        systemctl restart "${serviceName}.service"
        systemctl status "${serviceName}.service"
    fi
    sleep 5
}

extract_pvwaURL() {
    local config_file="$1"
    local componentName="$2"
    echo "***** Grabbing PVWA URL from: $configurationFile"
	# if file exists and can be read.
    if [ -r "$configurationFile" ] && [ -s "$configurationFile" ]; then
        # Grab only the first address if ini has multiple.
        if [[ $componentName == aim ]]; then
            pvwaURL=$(cat "$configurationFile" | grep "^ADDRESS" | cut -d'=' -f2 | cut -d',' -f1)
		else # must be psmp.
			pvwaURL=$(cat $configurationFile | grep -oP '(?<=ApplicationRoot=").*?(?=")')
		fi


		echo "Checking PVWA URL: $pvwaURL"
		# Remove trailing spaces
		pvwaURL=$(echo "$pvwaURL" | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
		echo "PVWA URL after trim: $pvwaURL"
		# Check if it's not in IP format; we need it for API calls.
		if echo "$pvwaURL" | egrep '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > /dev/null 2>&1; then
			read -r -p "Address is in IP format. Please enter the address in DNS format (example https://mikeb.cyberark.cloud): " pvwaURL
		else
			echo "Retrieved Address: $pvwaURL"
		fi

		
		# handle AIM since we grab vault address from vault.ini
		if [[ $pvwaURL == vault-* ]]; then
			# trim the "vault-" part
			pvwaURL="${pvwaURL#vault-}"
		else
			# If it doesn't start with "vault-", use the address as is
			pvwaURL="$pvwaURL"
		fi
		
		echo -e "***** PVWA URL is: ${GREEN}$pvwaURL${NC}"
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
		else
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
		fi
    else
		read -r -p "Couldn't grab PVWA URL, please enter it manually (e.g., https://mikeb.cyberark.cloud):" pvwaURL
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		# Check if URL belongs to UM env; otherwise, use legacy.
		if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
		else
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
		fi
	fi
}


# Function to prompt for custom values
prompt_for_custom_policy() {
    read -p "Enter minimum number of alphabetic characters (Default: $MinAlphabetic): " input
    MinAlphabetic=${input:-$MinAlphabetic}

    read -p "Enter minimum number of numeric characters (Default: $MinNumeric): " input
    MinNumeric=${input:-$MinNumeric}

    read -p "Enter minimum number of punctuation characters (Default: $MinPunctuation): " input
    MinPunctuation=${input:-$MinPunctuation}

    read -p "Enter minimum password length (Default: $MinLength): " input
    MinLength=${input:-$MinLength}

    read -p "Must mix case? (Yes/No, Default: $MustMixCase): " input
    MustMixCase=${input:-$MustMixCase}

    read -p "Enter minimum number of unique characters (Default: $MinUnique): " input
    MinUnique=${input:-$MinUnique}

    read -p "Enter maximum number of repeating characters (Default: $MaxRepeatingCharacters): " input
    MaxRepeatingCharacters=${input:-$MaxRepeatingCharacters}
}

generate_password() {
    local password=""
    local alphabetic_count=0
    local numeric_count=0
    local punctuation_count=0
    local unique_chars=()
    local last_char=""
    local repeat_count=0
    local iteration=0
    local max_iterations=1000  # Prevent infinite loops

    # Adjusted set of punctuation characters to exclude problematic ones
    local safe_punctuation="!@$%^&*()_+=[]{}|:,.?;-'\""
    local punctuation_length=${#safe_punctuation}

    password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 1)
    if [[ $password =~ [A-Za-z] ]]; then
        ((alphabetic_count++))
    else
        ((numeric_count++))
    fi
    unique_chars+=("$password")

    while : ; do
        ((iteration++))
        if [ $iteration -gt $max_iterations ]; then
            echo "Failed to generate password meeting criteria after $max_iterations attempts."
            return 1  # Indicate failure
        fi

        local char_type=$((RANDOM % 3))
        local char=""

        # Dynamically adjust character type selection based on current counts
        if [[ $alphabetic_count -lt $MinAlphabetic ]] || { [[ ${#password} -lt $MinLength ]] && [[ "$MustMixCase" == "Yes" ]]; }; then
            char_type=0
        elif [[ $numeric_count -lt $MinNumeric ]]; then
            char_type=1
        elif [[ $punctuation_count -lt $MinPunctuation ]]; then
            char_type=2
        fi

        case $char_type in
            0) char=$(tr -dc 'A-Za-z' </dev/urandom | head -c 1)
               ((alphabetic_count++));;
            1) char=$(tr -dc '0-9' </dev/urandom | head -c 1)
               ((numeric_count++));;
            2) # Select a random punctuation character from the adjusted set
               local rand=$((RANDOM % punctuation_length))
               char=${safe_punctuation:$rand:1}
               ((punctuation_count++));;
        esac

        if [[ $char == $last_char ]]; then
            ((repeat_count++))
            if [ $repeat_count -gt $MaxRepeatingCharacters ]; then
                continue
            fi
        else
            repeat_count=1
            last_char=$char
        fi

        password+=$char
        unique_chars+=("$char") # Simplify logic; duplicates handled elsewhere

        if [ ${#password} -ge $MinLength ] && [ $(printf "%s\n" "${unique_chars[@]}" | sort -u | wc -l) -ge $MinUnique ] &&
           ((alphabetic_count >= MinAlphabetic)) && ((numeric_count >= MinNumeric)) &&
           ((punctuation_count >= MinPunctuation)) &&
           ([[ $MustMixCase == "No" ]] || ([[ $password =~ [a-z] ]] && [[ $password =~ [A-Z] ]])); then
            echo $password
            return 0  # Success
        fi
    done
}

main_sync() {
    clear
    if [[ $component_provided -eq 1 ]]; then
        response="yes"
        echo "***** Component was provided via --Component, continuing with the synced reset flow."
    else
        echo "***** To perform this task, we must be able to reach your cloud portal (e.g., https://mikeb.privilegecloud.cyberark.cloud) via HTTPS/443."
        echo ""
        read -r -p "***** Do you want to continue? [Y/N] " response
    fi
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "***** Selected YES..."
        # Grab PVWA URL
        extract_pvwaURL "$configurationFile" "$component_name"

        # Check if the hostname is resolvable before proceeding
        check_dns_resolution "$pvwaURLAPI"

        # PVWA Login
        echo "***** Establishing connection to PVWA..."
        echo "***** Calling: $pvwaURLAPI"
        creds     # get user input
        pvwaLogin # call login
        if [[ $(echo "$rest" | grep "200") ]]; then
            echo -e "***** ${GREEN}Connected!${NC}"
            # Grab headers
            pvwaHeaders=$(echo "$rest" | cut -d' ' -f1 | tr -d '"')
        else
            echo -e "***** ${RED}Connection failed...${NC}"
            echo "http response code: $rest"
            echo -e "***** ${RED}Unable to proceed, fix connection to PVWA and rerun the script.${NC}"
            exit 1
        fi

        for n in ${credfiles[@]}; do #both app and gw
            echo "***** Generating CredFile: $n"
            if [ -s $n ]; then #check file not empty
                credUsername=$(cat $n | grep -oP '(?<=Username=).*(?=)')
                echo -e "***** Grabbed username: ${PURPLE}$credUsername${NC}"
                #generate random pw
                randomPW=$(generate_password)
                $createcredfile $n Password -Username "$credUsername" -Password "$randomPW" -EntropyFile
                #get user ID
                echo "***** Retrieving UserID for user $credUsername"
                pvwaGetUserId "$compUserType"
                userID=$(echo $pvwaGetUser | grep -oP '(?<="id":).*?(?=,)') # grabs user id
                echo "***** userID: $userID"
                echo "***** Activating/Unsuspending user: $credUsername just in case."
                pvwaActivateUser
                sleep 1
                if [[ $pvwaActivate == 200 ]]; then
                    echo -e "***** ${GREEN}Successfully Activated: $credUsername${NC}"
                else
                    echo -e "***** ${RED}Failed Activating: $credUsername${NC}"
                    echo $pvwaActivate
                    exit 1
                fi
                echo "***** Resetting Password user: $credUsername"
                pvwaResetPW # call reset pw
                sleep 1
                if [[ $(echo $pvwaReset | grep "200") ]]; then
					echo -e "***** ${GREEN}Successfully Reset Password: $credUsername${NC}"
				else
					if echo "$pvwaReset" | grep "Password must" > /dev/null 2>&1; then
						echo -e "***** ${RED}Failed Resetting Password due to complexity requirements: $credUsername${NC}"
						echo "$pvwaReset"
						# Prompt for custom complexity and retry
						echo ""
						echo -e "${PURPLE}Let's adjust the password complexity to accommodate the vault requirements, please approve or set new value one by one:${NC}"
						prompt_for_custom_policy
						randomPW=$(generate_password)
						$createcredfile $n Password -Username "$credUsername" -Password "$randomPW" -EntropyFile
						# Retry password reset with the new password
						echo "***** Retrying with adjusted complexity..."
						pvwaResetPW
						if [[ $(echo $pvwaReset | grep "200") ]]; then
							echo -e "***** ${GREEN}Successfully Reset Password after adjusting complexity: $credUsername${NC}"
						else
							echo -e "***** ${RED}Failed Resetting Password after adjusting complexity: $credUsername${NC}"
							echo $pvwaReset
							exit 1
						fi
					else
						echo -e "***** ${RED}Failed Resetting Password: $credUsername${NC}"
						echo $pvwaReset
						exit 1
					fi
				fi
            else
                echo "***** File is empty or corrupted, aborting..."
                exit 1
            fi
        done

        restart_services "$service"
        echo "***** Checking to see if service is back online via SystemHealth."
        pvwaSystemHealthUser "$appName"
        # grab only relevant username and cut everything except IsLoggedOn "true" or "false"
        appName=$(echo $credUsername | cut -d'_' -f2) #better to search the exact name instead of with app/gw prefix.
        status=$(echo $pvwaSystemHealth | grep -oP "($appName).*?(?="LastLogonDate")" | grep -oP '(?<="IsLoggedOn":).*?(?=,)')
        if [[ $(echo $status | grep "true") ]]; then
            echo -e "***** ${GREEN}$appName Is : Online!${NC}"
        else
            echo -e "***** ${RED}$appName Is : Offline!${NC}"
            echo -e "***** ${RED}Return call was: $status${NC}"
            echo -e "***** Something went wrong :( you'll have to reset it manually with CyberArk's help."
            pvwaLogoff
            exit 1
        fi
        # Logoff
        pvwaLogoff
        exit 0

    else
        echo "***** Selected NO..."
        echo "***** Exiting..."
        exit 1
    fi
}

main_local_only() {
    echo "***** Running local-only cred reset. Backend vault passwords will not be changed."
    resolve_offline_password

    for n in "${credfiles[@]}"; do
        echo "***** Generating local CredFile: $n"
        if [[ -s "$n" ]]; then
            credUsername=$(grep -oP '(?<=Username=).*(?=)' "$n")
            if [[ -z "$credUsername" ]]; then
                read -r -p "Enter the relevant user name for CredFile '$n': " credUsername
            fi
            if [[ -z "$credUsername" ]]; then
                echo "Username is empty, aborting."
                exit 1
            fi
            echo -e "***** Using username: ${PURPLE}$credUsername${NC}"
            "$createcredfile" "$n" Password -Username "$credUsername" -Password "$offline_cred_password" -EntropyFile
        else
            echo "***** File is empty or corrupted, aborting..."
            exit 1
        fi
    done

    restart_services "$service"
    echo -e "***** ${GREEN}Successfully reset local cred file(s) for $component_name without backend changes.${NC}"
}

if [ "$EUID" -ne 0 ]; then
    read -p "***** Please run as root - Press ENTER to exit..."
    exit 1
fi

parse_args "$@"

# check we are not running from /tmp/ folder, its notorious for permission issues.
if [[ $PWD = /tmp ]] || [[ $PWD = /tmp/* ]]; then
    read -p "***** Detected /tmp folder, it is known for problematic permission issues, please move to another folder and try again...."
    exit 1
fi

clear
echo "--------------------------------------------------------------"
echo "----------- CyberArk CreateCredFile-Helper for NIX -----------"
echo "----------- Script version "$scriptVersion" ---------------------------------"
echo "--------------------------------------------------------------"

declare -a components_found=()

# Check if CARKpsmp component exists
if [ -f "/opt/CARKpsmp/bin/createcredfile" ]; then
    components_found+=("psmp")
fi

# Check if CARKaim component exists
if [ -f "/opt/CARKaim/bin/createcredfile" ]; then
    components_found+=("aim")
fi

# If no components are found, exit
if [ ${#components_found[@]} -eq 0 ]; then
    echo "No CyberArk services detected."
    exit 1
fi

if [[ $component_provided -eq 1 ]]; then
    component_name="$selected_component"
    if [[ ! " ${components_found[*]} " =~ [[:space:]]${component_name}[[:space:]] ]]; then
        echo "Component '$component_name' was provided via --Component but was not detected on this machine."
        exit 1
    fi
    echo "Component '$component_name' was selected via --Component."
else
    # List the components found and prompt for user selection
    echo "CyberArk services detected on this machine:"
    for i in "${!components_found[@]}"; do
        echo -e "${GREEN}$((i+1)). ${components_found[i]}${NC}"
    done

    read -p "Please choose a service to reset cred files (1-${#components_found[@]}): " choice
    component_name="${components_found[$((choice-1))]}"
fi

# Set the variables based on the user's choice
case $component_name in
    "psmp")
        echo "CARKpsmp component selected."
        credfiles=("/etc/opt/CARKpsmp/vault/psmpappuser.cred" "/etc/opt/CARKpsmp/vault/psmpgwuser.cred")
        createcredfile="/opt/CARKpsmp/bin/createcredfile"
        configurationFile="/var/opt/CARKpsmp/temp/PVConfiguration.xml"
        service="psmpsrv"
        appName="SessionManagement"
		compUserType="PSMPServer"
        ;;
    "aim")
        echo "CARKaim component selected."
        credfiles=("/etc/opt/CARKaim/vault/appprovideruser.cred")
        createcredfile="/opt/CARKaim/bin/createcredfile"
        configurationFile="/etc/opt/CARKaim/vault/vault.ini"
        service="aimprv"
        appName="AIM"
		compUserType="AppProvider"
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

if [[ $reset_local_only -eq 1 ]]; then
    main_local_only
else
    main_sync
fi
