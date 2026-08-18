#!/usr/bin/ksh

# AIX-native command path. /opt/freeware is intentionally NOT preferred here.
PATH=/usr/bin:/bin:/usr/sbin:/etc:$PATH
export PATH
LC_ALL=C
export LC_ALL


check_prerequisites() {
    echo "***** Checking AIX prerequisites..."

    if [ "$(uname -s)" != "AIX" ]; then
        echo "ERROR: This version is intended for AIX only."
        exit 1
    fi

    if [ -x /usr/bin/ksh ]; then
        :
    else
        echo "ERROR: /usr/bin/ksh was not found."
        exit 1
    fi

    CURL="$(command -v curl 2>/dev/null)"
    if [ -z "$CURL" ] && [ -x /opt/freeware/bin/curl ]; then
        CURL=/opt/freeware/bin/curl
    fi

    if [ -z "$CURL" ]; then
        echo "ERROR: curl was not found."
        echo "The PVWA API calls in this script require curl."
        exit 1
    fi

    if ! "$CURL" --version >/dev/null 2>&1; then
        echo "ERROR: curl was found but could not be executed: $CURL"
        exit 1
    fi

    echo "***** curl detected: $CURL"

    if [ ! -r /dev/urandom ]; then
        echo "ERROR: /dev/urandom is not available or cannot be read."
        exit 1
    fi

    for cmd in awk sed grep cut tr head sort wc ping stty id; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "ERROR: Required AIX command '$cmd' was not found."
            exit 1
        fi
    done

    if [ "$(uname -s)" = "AIX" ]; then
        for cmd in stopsrc startsrc lssrc; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                echo "ERROR: AIX SRC command '$cmd' was not found."
                exit 1
            fi
        done
    fi

    echo "***** All AIX prerequisite checks passed."
    echo ""
}

is_yes() {
    typeset answer
    answer=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$answer" in
        y|yes) return 0 ;;
        *)     return 1 ;;
    esac
}

###########################################################################
#
# NAME: CyberArk Privilege Cloud CreateCredFile-Helper AIX Edition
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
    typeset payload
    payload=$(cat <<EOF
{
	"username": "$adminuser",
	"password": "$adminpass",
	"concurrentSession": "false"
}
EOF
)
    rest=$("$CURL" --location -k -m 40 --connect-timeout 5 -s --request POST --write-out " %{http_code}" "$pvwaURLAPI/Auth/CyberArk/Logon" \
        --header "Content-Type: application/json" \
        --data "$payload")
}

pvwaLogoff() {
    pvwaActivate=$(
        "$CURL" --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --write-out "%{http_code}" "$pvwaURLAPI/Auth/Logoff" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaGetUserId() {
# Call based on UserType (AppProvider, PSMServer etc')
typeset UserType="$1"
    pvwaGetUser=$(
        "$CURL" --location -k -m 40 --connect-timeout 5 -s --request GET --write-out " %{http_code}" "$pvwaURLAPI/Users?filter=componentUser&search=$credUsername&UserType=$UserType" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaActivateUser() {
    pvwaActivate=$(
        "$CURL" --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --write-out "%{http_code}" "$pvwaURLAPI/Users/$userID/Activate" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaResetPW() {
    typeset payload
    payload=$(cat <<EOF
{
	"id": "$userID",
	"newPassword": "$randomPW",
	"concurrentSession": "false"
}
EOF
)
    pvwaReset=$("$CURL" --location -k -m 40 --connect-timeout 5 -s --request POST --write-out "%{http_code}" "$pvwaURLAPI/Users/$userID/ResetPassword" \
        --header "Content-Type: application/json" \
        --header "Authorization: $pvwaHeaders" \
        --data "$payload")
}

pvwaSystemHealthUser() {
    typeset app_name="$1"
    pvwaSystemHealth=$(
        "$CURL" --location -k -m 40 --connect-timeout 5 -s --request GET --write-out " %{http_code}" "$pvwaURLAPI/ComponentsMonitoringDetails/$app_name" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

# Function to check DNS resolution of a URL
check_dns_resolution() {
    typeset url="$1"
    typeset hostname
    hostname=$(echo "$url" | awk -F/ '{print $3}')
	# Remove .privilegecloud from the hostname
    hostname=$(printf '%s\n' "$hostname" | sed 's/\.privilegecloud//g')
	
	echo "***** Checking we are able to resolve address $hostname"
    if ping -c 1 "$hostname" >/dev/null; then
        printf "%b\n" "***** ${GREEN}Hostname ($hostname) resolved successfully.${NC}"
    else
        printf "%b\n" "${RED}Can't resolve hostname ($hostname). Please check DNS settings. Aborting...${NC}"
        printf "%s" "**** Proceed anyway?: [Y/N]: "
        IFS= read -r response
		if is_yes "$response"; then
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
    printf "%s" "Please Enter Privilege Cloud Install Username: "
    IFS= read -r adminuser
    echo " "
    echo "***** Please Enter Privilege Cloud Install User Password and press ENTER *****"
    stty -echo
    IFS= read -r adminpass
    stty echo
    echo ""
    if [ -z "$adminpass" ]; then
        echo "password is empty, rerun script"
        exit 1
    else
        adminpw="$(printf '%s' "$adminpass" | tr -d '[:space:]')"
    fi
}

usage() {
    cat <<'EOF'
Usage:
  ./createCredFile-Helper.sh [--Component psmp|aim] [--ResetCredLocalOnly] [--OfflineCredPassword env:VAR_NAME]

Examples:
  ./createCredFile-Helper.sh --Component psmp
  stty -echo; IFS= read -r OFFLINE_CRED_PASSWORD; stty echo; echo; export OFFLINE_CRED_PASSWORD; ./createCredFile-Helper.sh --ResetCredLocalOnly --Component psmp --OfflineCredPassword env:OFFLINE_CRED_PASSWORD; unset OFFLINE_CRED_PASSWORD
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -ResetCredLocalOnly|--ResetCredLocalOnly)
                reset_local_only=1
                ;;
            -Component|--Component)
                shift
                if [ -z "$1" ]; then
                    echo "Missing value for --Component."
                    usage
                    exit 1
                fi
                selected_component=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
                component_provided=1
                ;;
            -OfflineCredPassword|--OfflineCredPassword)
                shift
                if [ -z "$1" ]; then
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

    if [ "$component_provided" -eq 1 ] && [ "$selected_component" != "psmp" ] && [ "$selected_component" != "aim" ]; then
        echo "Invalid component '$selected_component'. Allowed values on AIX are: psmp, aim."
        exit 1
    fi

    if [ -n "$offline_cred_password_arg" ] && [ "$reset_local_only" -ne 1 ]; then
        echo "--OfflineCredPassword can only be used together with --ResetCredLocalOnly."
        exit 1
    fi
}

resolve_offline_password() {
    if [ -n "$offline_cred_password_arg" ]; then
        case "$offline_cred_password_arg" in
            env:*)
                typeset var_name="${offline_cred_password_arg#env:}"
                case "$var_name" in
                    ""|[0-9]*|*[!A-Za-z0-9_]*)
                        echo "Invalid environment variable name in '$offline_cred_password_arg'."
                        exit 1
                        ;;
                esac
                eval "offline_cred_password=\${$var_name-}"
                if [ -z "$offline_cred_password" ]; then
                    echo "The environment variable reference '$offline_cred_password_arg' is empty or not set."
                    echo "Example: stty -echo; IFS= read -r OFFLINE_CRED_PASSWORD; stty echo; echo; export OFFLINE_CRED_PASSWORD; ./createCredFile-Helper.sh --ResetCredLocalOnly --Component psmp --OfflineCredPassword env:OFFLINE_CRED_PASSWORD; unset OFFLINE_CRED_PASSWORD"
                    exit 1
                fi
                : # value already resolved above
                ;;
            *)
                echo "Plain text passwords are not allowed with --OfflineCredPassword."
                echo "Use an environment variable reference instead."
                echo "Example: stty -echo; IFS= read -r OFFLINE_CRED_PASSWORD; stty echo; echo; export OFFLINE_CRED_PASSWORD; ./createCredFile-Helper.sh --ResetCredLocalOnly --Component psmp --OfflineCredPassword env:OFFLINE_CRED_PASSWORD; unset OFFLINE_CRED_PASSWORD"
                exit 1
                ;;
        esac
    else
        printf "%s" "Enter the password that should be written into the local cred file(s): "
        stty -echo
        IFS= read -r offline_cred_password
        stty echo
        echo ""
        echo ""
        if [ -z "$offline_cred_password" ]; then
            echo "Password is empty, aborting."
            exit 1
        fi
    fi
}

restart_services() {
    typeset serviceName="$1"

    echo "***** Restarting $serviceName Service on AIX..."
    stopsrc -s "$serviceName"
    startsrc -s "$serviceName"
    lssrc -s "$serviceName"

    sleep 5
}

extract_pvwaURL() {
    typeset config_file="$1"
    typeset componentName="$2"
    echo "***** Grabbing PVWA URL from: $configurationFile"
	# if file exists and can be read.
    if [ -r "$configurationFile" ] && [ -s "$configurationFile" ]; then
        # Grab only the first address if ini has multiple.
        if [ "$componentName" = "aim" ]; then
            pvwaURL=$(grep "^ADDRESS" "$configurationFile" | cut -d'=' -f2 | cut -d',' -f1)
		else # must be psmp.
			pvwaURL=$(sed -n 's/.*ApplicationRoot="\([^"]*\)".*/\1/p' "$configurationFile" | sed -n '1p')
		fi


		echo "Checking PVWA URL: $pvwaURL"
		# Remove trailing spaces
		pvwaURL=$(echo "$pvwaURL" | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
		echo "PVWA URL after trim: $pvwaURL"
		# Check if it's not in IP format; we need it for API calls.
		if echo "$pvwaURL" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > /dev/null 2>&1; then
			printf "%s" "Address is in IP format. Please enter the address in DNS format (example https://mikeb.cyberark.cloud): "
			IFS= read -r pvwaURL
		else
			echo "Retrieved Address: $pvwaURL"
		fi

		
		# handle AIM since we grab vault address from vault.ini
		case "$pvwaURL" in
			vault-*) pvwaURL="${pvwaURL#vault-}" ;;
		esac
		
		printf "%b\n" "***** PVWA URL is: ${GREEN}$pvwaURL${NC}"
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		case "$pvwaURL" in
			*cyberark.cloud*) pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api ;;
			*)               pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api ;;
		esac
    else
		printf "%s" "Couldn't grab PVWA URL, please enter it manually (e.g., https://mikeb.cyberark.cloud):"
		IFS= read -r pvwaURL
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		# Check if URL belongs to UM env; otherwise, use legacy.
		case "$pvwaURL" in
			*cyberark.cloud*) pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api ;;
			*)               pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api ;;
		esac
	fi
}


# Function to prompt for custom values
prompt_for_custom_policy() {
    printf "%s" "Enter minimum number of alphabetic characters (Default: $MinAlphabetic): "
    IFS= read -r input
    MinAlphabetic=${input:-$MinAlphabetic}

    printf "%s" "Enter minimum number of numeric characters (Default: $MinNumeric): "
    IFS= read -r input
    MinNumeric=${input:-$MinNumeric}

    printf "%s" "Enter minimum number of punctuation characters (Default: $MinPunctuation): "
    IFS= read -r input
    MinPunctuation=${input:-$MinPunctuation}

    printf "%s" "Enter minimum password length (Default: $MinLength): "
    IFS= read -r input
    MinLength=${input:-$MinLength}

    printf "%s" "Must mix case? (Yes/No, Default: $MustMixCase): "
    IFS= read -r input
    MustMixCase=${input:-$MustMixCase}

    printf "%s" "Enter minimum number of unique characters (Default: $MinUnique): "
    IFS= read -r input
    MinUnique=${input:-$MinUnique}

    printf "%s" "Enter maximum number of repeating characters (Default: $MaxRepeatingCharacters): "
    IFS= read -r input
    MaxRepeatingCharacters=${input:-$MaxRepeatingCharacters}
}

generate_password() {
    typeset password=""
    typeset alphabetic_count=0
    typeset numeric_count=0
    typeset punctuation_count=0
    typeset unique_chars=""
    typeset unique_count=0
    typeset last_char=""
    typeset repeat_count=0
    typeset iteration=0
    typeset max_iterations=1000
    typeset safe_punctuation='!@$%^&*()_+=[]{}|:,.?;-'
    typeset punctuation_length=${#safe_punctuation}
    typeset char_type
    typeset char
    typeset rand
    typeset char_pos

    password=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 1)

    case "$password" in
        *[A-Za-z]*) alphabetic_count=$((alphabetic_count + 1)) ;;
        *)          numeric_count=$((numeric_count + 1)) ;;
    esac

    unique_chars="$password"
    unique_count=1
    last_char="$password"
    repeat_count=1

    while : ; do
        iteration=$((iteration + 1))
        if [ "$iteration" -gt "$max_iterations" ]; then
            echo "Failed to generate password meeting criteria after $max_iterations attempts."
            return 1
        fi

        char_type=$((RANDOM % 3))
        char=""

        if [ "$alphabetic_count" -lt "$MinAlphabetic" ]; then
            char_type=0
        elif [ "$numeric_count" -lt "$MinNumeric" ]; then
            char_type=1
        elif [ "$punctuation_count" -lt "$MinPunctuation" ]; then
            char_type=2
        elif [ "${#password}" -lt "$MinLength" ] && [ "$MustMixCase" = "Yes" ]; then
            case "$password" in
                *[a-z]*)
                    case "$password" in
                        *[A-Z]*) : ;;
                        *) char_type=0 ;;
                    esac
                    ;;
                *) char_type=0 ;;
            esac
        fi

        case "$char_type" in
            0)
                char=$(tr -dc 'A-Za-z' </dev/urandom | head -c 1)
                alphabetic_count=$((alphabetic_count + 1))
                ;;
            1)
                char=$(tr -dc '0-9' </dev/urandom | head -c 1)
                numeric_count=$((numeric_count + 1))
                ;;
            2)
                rand=$((RANDOM % punctuation_length))
                char_pos=$((rand + 1))
                char=$(printf '%s' "$safe_punctuation" | cut -c "$char_pos")
                punctuation_count=$((punctuation_count + 1))
                ;;
        esac

        if [ "$char" = "$last_char" ]; then
            repeat_count=$((repeat_count + 1))
            if [ "$repeat_count" -gt "$MaxRepeatingCharacters" ]; then
                continue
            fi
        else
            repeat_count=1
            last_char="$char"
        fi

        password="${password}${char}"

        case "$unique_chars" in
            *"$char"*) : ;;
            *)
                unique_chars="${unique_chars}${char}"
                unique_count=$((unique_count + 1))
                ;;
        esac

        if [ "${#password}" -ge "$MinLength" ] &&
           [ "$unique_count" -ge "$MinUnique" ] &&
           [ "$alphabetic_count" -ge "$MinAlphabetic" ] &&
           [ "$numeric_count" -ge "$MinNumeric" ] &&
           [ "$punctuation_count" -ge "$MinPunctuation" ]; then

            if [ "$MustMixCase" = "No" ]; then
                echo "$password"
                return 0
            fi

            case "$password" in
                *[a-z]*)
                    case "$password" in
                        *[A-Z]*)
                            echo "$password"
                            return 0
                            ;;
                    esac
                    ;;
            esac
        fi
    done
}

main_sync() {
    clear
    if [ "$component_provided" -eq 1 ]; then
        response="yes"
        echo "***** Component was provided via --Component, continuing with the synced reset flow."
    else
        echo "***** To perform this task, we must be able to reach your cloud portal (e.g., https://mikeb.privilegecloud.cyberark.cloud) via HTTPS/443."
        echo ""
        printf "%s" "***** Do you want to continue? [Y/N] "
        IFS= read -r response
    fi
    if is_yes "$response"; then
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
        if printf '%s\n' "$rest" | grep "200" >/dev/null 2>&1; then
            printf "%b\n" "***** ${GREEN}Connected!${NC}"
            # Grab headers
            pvwaHeaders=$(echo "$rest" | cut -d' ' -f1 | tr -d '"')
        else
            printf "%b\n" "***** ${RED}Connection failed...${NC}"
            echo "http response code: $rest"
            printf "%b\n" "***** ${RED}Unable to proceed, fix connection to PVWA and rerun the script.${NC}"
            exit 1
        fi

        for n in $credfiles; do #both app and gw
            echo "***** Generating CredFile: $n"
            if [ -s "$n" ]; then #check file not empty
                credUsername=$(awk -F'Username=' 'NF > 1 { print $2; exit }' "$n")
                printf "%b\n" "***** Grabbed username: ${PURPLE}$credUsername${NC}"
                #generate random pw
                randomPW=$(generate_password)
                "$createcredfile" "$n" Password -Username "$credUsername" -Password "$randomPW" -EntropyFile
                #get user ID
                echo "***** Retrieving UserID for user $credUsername"
                pvwaGetUserId "$compUserType"
                userID=$(printf '%s\n' "$pvwaGetUser" | sed -n 's/.*"id":[[:space:]]*\([^,}]*\).*/\1/p') # grabs user id
                echo "***** userID: $userID"
                echo "***** Activating/Unsuspending user: $credUsername just in case."
                pvwaActivateUser
                sleep 1
                if [ "$pvwaActivate" = "200" ]; then
                    printf "%b\n" "***** ${GREEN}Successfully Activated: $credUsername${NC}"
                else
                    printf "%b\n" "***** ${RED}Failed Activating: $credUsername${NC}"
                    echo "$pvwaActivate"
                    exit 1
                fi
                echo "***** Resetting Password user: $credUsername"
                pvwaResetPW # call reset pw
                sleep 1
                if printf '%s\n' "$pvwaReset" | grep "200" >/dev/null 2>&1; then
					printf "%b\n" "***** ${GREEN}Successfully Reset Password: $credUsername${NC}"
				else
					if echo "$pvwaReset" | grep "Password must" > /dev/null 2>&1; then
						printf "%b\n" "***** ${RED}Failed Resetting Password due to complexity requirements: $credUsername${NC}"
						echo "$pvwaReset"
						# Prompt for custom complexity and retry
						echo ""
						printf "%b\n" "${PURPLE}Let's adjust the password complexity to accommodate the vault requirements, please approve or set new value one by one:${NC}"
						prompt_for_custom_policy
						randomPW=$(generate_password)
						"$createcredfile" "$n" Password -Username "$credUsername" -Password "$randomPW" -EntropyFile
						# Retry password reset with the new password
						echo "***** Retrying with adjusted complexity..."
						pvwaResetPW
						if printf '%s\n' "$pvwaReset" | grep "200" >/dev/null 2>&1; then
							printf "%b\n" "***** ${GREEN}Successfully Reset Password after adjusting complexity: $credUsername${NC}"
						else
							printf "%b\n" "***** ${RED}Failed Resetting Password after adjusting complexity: $credUsername${NC}"
							echo "$pvwaReset"
							exit 1
						fi
					else
						printf "%b\n" "***** ${RED}Failed Resetting Password: $credUsername${NC}"
						echo "$pvwaReset"
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
        appName=$(printf '%s\n' "$credUsername" | cut -d'_' -f2) #better to search the exact name instead of with app/gw prefix.
        status=$(printf '%s\n' "$pvwaSystemHealth" | sed -n "s/.*$appName.*\"IsLoggedOn\":[[:space:]]*\([^,}]*\).*/\1/p")
        if printf '%s\n' "$status" | grep "true" >/dev/null 2>&1; then
            printf "%b\n" "***** ${GREEN}$appName Is : Online!${NC}"
        else
            printf "%b\n" "***** ${RED}$appName Is : Offline!${NC}"
            printf "%b\n" "***** ${RED}Return call was: $status${NC}"
            printf "%b\n" "***** Something went wrong :( you'll have to reset it manually with CyberArk's help."
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

    for n in $credfiles; do
        echo "***** Generating local CredFile: $n"
        if [ -s "$n" ]; then
            credUsername=$(awk -F'Username=' 'NF > 1 { print $2; exit }' "$n")
            if [ -z "$credUsername" ]; then
                printf "%s" "Enter the relevant user name for CredFile '$n': "
                IFS= read -r credUsername
            fi
            if [ -z "$credUsername" ]; then
                echo "Username is empty, aborting."
                exit 1
            fi
            printf "%b\n" "***** Using username: ${PURPLE}$credUsername${NC}"
            "$createcredfile" "$n" Password -Username "$credUsername" -Password "$offline_cred_password" -EntropyFile
        else
            echo "***** File is empty or corrupted, aborting..."
            exit 1
        fi
    done

    restart_services "$service"
    printf "%b\n" "***** ${GREEN}Successfully reset local cred file(s) for $component_name without backend changes.${NC}"
}

check_prerequisites

if [ "$(id -u)" -ne 0 ]; then
    printf "%s" "***** Please run as root - Press ENTER to exit..."
    IFS= read -r response
    exit 1
fi

parse_args "$@"

# check we are not running from /tmp/ folder, its notorious for permission issues.
case "$PWD" in
    /tmp|/tmp/*)
        printf "%s" "***** Detected /tmp folder, it is known for problematic permission issues, please move to another folder and try again...."
        IFS= read -r response
        exit 1
        ;;
esac

clear
echo "--------------------------------------------------------------"
echo "----------- CyberArk CreateCredFile-Helper for AIX -----------"
echo "----------- Script version "$scriptVersion" ---------------------------------"
echo "--------------------------------------------------------------"

components_found=""
components_count=0

# Check if CARKpsmp component exists
if [ -f "/opt/CARKpsmp/bin/createcredfile" ]; then
    components_found="${components_found} psmp"
    components_count=$((components_count + 1))
fi

# Check if CARKaim component exists
if [ -f "/opt/CARKaim/bin/createcredfile" ]; then
    components_found="${components_found} aim"
    components_count=$((components_count + 1))
fi

# If no components are found, exit
if [ "$components_count" -eq 0 ]; then
    echo "No CyberArk services detected."
    exit 1
fi

if [ "$component_provided" -eq 1 ]; then
    component_name="$selected_component"

    case " $components_found " in
        *" $component_name "*) : ;;
        *)
            echo "Component '$component_name' was provided via --Component but was not detected on this machine."
            exit 1
            ;;
    esac

    echo "Component '$component_name' was selected via --Component."
else
    echo "CyberArk services detected on this machine:"
    i=1
    for component in $components_found; do
        printf "%b\n" "${GREEN}${i}. ${component}${NC}"
        i=$((i + 1))
    done

    printf "%s" "Please choose a service to reset cred files (1-${components_count}): "
    IFS= read -r choice

    case "$choice" in
        ''|*[!0-9]*)
            echo "Invalid choice."
            exit 1
            ;;
    esac

    if [ "$choice" -lt 1 ] || [ "$choice" -gt "$components_count" ]; then
        echo "Invalid choice."
        exit 1
    fi

    i=1
    component_name=""
    for component in $components_found; do
        if [ "$i" -eq "$choice" ]; then
            component_name="$component"
            break
        fi
        i=$((i + 1))
    done
fi

# Set the variables based on the user's choice
case $component_name in
    "psmp")
        echo "CARKpsmp component selected."
        credfiles="/etc/opt/CARKpsmp/vault/psmpappuser.cred /etc/opt/CARKpsmp/vault/psmpgwuser.cred"
        createcredfile="/opt/CARKpsmp/bin/createcredfile"
        configurationFile="/var/opt/CARKpsmp/temp/PVConfiguration.xml"
        service="psmpsrv"
        appName="SessionManagement"
		compUserType="PSMPServer"
        ;;
    "aim")
        echo "CARKaim component selected."
        credfiles="/etc/opt/CARKaim/vault/appprovideruser.cred"
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

if [ "$reset_local_only" -eq 1 ]; then
    main_local_only
else
    main_sync
fi
