#!/bin/sh

# Copyright Check Point Software Technologies LTD
FILESYSTEM_PATH="/etc/cp"
LOG_FILE_PATH="/var/log"
USR_LIB_PATH="/usr/lib"
USR_SBIN_PATH="/usr/sbin"
INIT_D_PATH="/etc/init.d"
CONF_PATH="conf"
CERTS_PATH="certs"
DATA_PATH="data"
LOG_PATH="nano_agent"
SCRIPTS_PATH="scripts"
WATCHDOG_PATH="watchdog"
SERVICE_PATH="orchestration"
DBG_FILE_PATH="${LOG_PATH}/cp-nano-orchestration.dbg"
ENV_DETAILS_FILE="${CONF_PATH}/environment-details.cfg"
WATCHDOG_MAX_ROTATIONS=10
WATCHDOG_MAX_FILE_SIZE=4096
FORCE_CLEAN_FLAG='^(--force-clean|-f)$'

is_wlp_orchestration="false"
ORCHESTRATION_EXE_SOURCE_PATH="./bin/orchestration_comp"

NGINX_METADAT_EXTRACTOR_PATH="./scripts/cp-nano-makefile-generator.sh"
ORCHESTRATION_FILE_NAME="cp-nano-orchestration"
NGINX_METADDATA_EXTRACTOR_NAME="cp-nano-makefile-generator.sh"
AGENT_UNINSTALL="cp-agent-uninstall.sh"
ORCHESTRATION_NAME="orchestration"
CP_AGENT_INFO_NAME="cp-agent-info"
CP_PACKAGE_LIST_NAME="cp-nano-package-list"

BIN_PATH="bin"
INSTALLATION_LOG_FILE="cp-nano-agent-install.log"
DEBUG_FLAG='^(--debug|-d)$'
FORCE_STDOUT=true
CP_NANO_DEBUG="cpnano_debug"
CP_NANO_BASE64="cpnano_base64"
EGG_MODE=
ORCHESTRATION_CONF_FILE="${CONF_PATH}/cp-nano-orchestration-conf.json"
ORCHESTRATION_DEBUG_CONF_FILE="${CONF_PATH}/cp-nano-orchestration-debug-conf.json"
DEFAULT_SETTINGS_PATH="${CONF_PATH}/settings.json"
var_default_gem_fog_address="https://inext-agents.cloud.ngen.checkpoint.com"
var_default_us_fog_address="https://inext-agents-us.cloud.ngen.checkpoint.com"
var_default_au_fog_address="https://inext-agents-aus1.cloud.ngen.checkpoint.com"
var_default_in_fog_address="https://inext-agents-ind1.cloud.ngen.checkpoint.com"
var_fog_address=
var_certs_dir=
var_public_key=
var_sleep_interval=30
var_error_sleep_interval=30
var_upgrade_mode=
var_token=
var_email=
var_server=
var_installation_debug_mode=false
var_startup_service=
var_arch_flag=
var_arch="x86"
var_offline_mode=false
var_hybrid_mode=false
var_orchestration_mode="online_mode"
var_container_mode=false
var_no_otp=false
var_additional_flags=
var_proxy=
var_compact_mode=false
var_skip_registration=false
var_is_alpine=false
var_gaia_release=1
var_mds_release=1
var_alpine_release=1
var_which_cmd_exists=0

if [ -f /.dockerenv ]; then
    var_container_mode=true
fi

IS_K8S_ENV=false
K8S_TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
if [ -f $K8S_TOKEN_PATH ]; then
    IS_K8S_ENV=true
fi

# Prerequisites for installation
cur_uid=$(id -u)
if [ "${cur_uid}" != "0" ]; then
    cp_print "Error, cp-nano-agent service installation requires root permissions, please re-run as root" ${FORCE_STDOUT}
    exit 1
fi

ls -l /etc/ | grep release > /dev/null 2>&1
retval=$?

if [ $retval -eq 0 ]; then
    cat /etc/*release | grep -q "Gaia"
    var_gaia_release=$?
    cat /etc/*release | grep -q "Multi-Domain Security Management"
    var_mds_release=$?
    cat /etc/*release | grep -q alpine
    var_alpine_release=$?
fi

if [ $var_gaia_release -eq 0 ] || [ $var_mds_release -eq 0 ]; then
    var_arch="gaia"
    var_arch_flag="--gaia"
elif [ $var_alpine_release -eq 0 ]; then
    var_is_alpine=true
else
    var_arch=$(uname -a | awk '{print $(NF -1) }')
    if [ -z "${var_arch}" ]; then
        var_arch="x86"
    fi

    if [ -n "$(echo "${var_arch}" | grep -i arm)" ]; then
        var_arch="arm"
    fi
fi

is_smb=0
if [ -f /pfrm2.0/bin/cposd ]; then
    is_smb=1
    if [ "$is_smb" = "1" ]; then
        if [ `fw_printenv -n sub_hw_ver` = "THX2" ]; then
            export LD_LIBRARY_PATH="/lib64:/pfrm2.0/lib64:${LD_LIBRARY_PATH}"
        fi
    fi
    var_arch="smb"
fi

usage()
{
    echo "Usage:"
    echo "--install                           : Install Nano Agent"
    echo "--uninstall                         : Remove Nano Agent"
    echo "--token <token>                     : Registration token"
    echo "--fog <fog URL>                     : Fog Address"
    echo "--email <email address>             : Contact Information"
    echo "--certs-dir <Trusted CA directory>  : Path to the trusted CA directory"
    echo "--public-key <Public key file path> : Path to the SSL certificate's public key file (PEM format)"
    echo "--ignore <ignore packages list>     : List of ignored packages"
    exit 1
}

starts_with() # Initials - sw
{
    sw_str=$1
    sw_prefix=$2
    if [ -z "$(echo "$sw_str" | sed 's|^'"$sw_prefix"'.*||')" ]; then
        echo true
    else
        echo false
    fi
}

verify_proxy_config()
{
    if [ "$var_proxy" = 'none' ]; then
        return
    fi

    if [ -n "$var_proxy" ]; then
        # Check if it is authenticated proxy
        without_http="$(echo "$var_proxy" | cut -d'/' -f 3)"
        user_pass="$(echo "$without_http" | cut -d'@' -f 1)"
        ip_port="$(echo "$without_http" | cut -d'@' -f 2)"

        # Authenticated proxy
        if [ "$var_proxy" = 'http://'"$user_pass"'@'"$ip_port" ] && [ -n "$user_pass" ] && [ -n "$ip_port" ]; then
            user="$(echo "$user_pass" | cut -d':' -f 1)"
            pass="$(echo "$user_pass" | cut -d':' -f 2)"
            if [ "$user_pass" != "$user"':'"$pass" ] || [ -z "$user" ] || [ -z "$pass" ]; then
                echo "Installation Error: Bad proxy syntax. Syntax must be http://[user:pass@]domain[:port]"
                exit 1
            fi
        elif [ "$(starts_with "$var_proxy" 'http://'"$ip_port")" = "false" ]; then
            echo "Installation Error: Bad proxy syntax. Syntax must be http://[user:pass@]domain[:port]"
            exit 1
        fi
    fi
}

save_local_policy_config()
{
    custom_policy_conf_file=${FILESYSTEM_PATH}/${CONF_PATH}/custom_policy.cfg
    var_policy_file=${FILESYSTEM_PATH}/${CONF_PATH}/local_policy.yaml
    echo "var_policy_file=${var_policy_file}" > ${custom_policy_conf_file}
    echo "last_local_policy_modification_time=$(stat -c %Y ${var_policy_file})" >> ${custom_policy_conf_file}
}

[ -f /etc/environment ] && . "/etc/environment"
if [ -n "${CP_ENV_FILESYSTEM}" ] ; then
    FILESYSTEM_PATH=$CP_ENV_FILESYSTEM
fi
if [ -n "${CP_ENV_LOG_FILE}" ] ; then
    LOG_FILE_PATH=$CP_ENV_LOG_FILE
fi
if [ -n "${CP_USR_LIB_PATH}" ]; then
    USR_LIB_PATH=$CP_USR_LIB_PATH
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CP_USR_LIB_PATH/cpnano
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CP_USR_LIB_PATH
fi
if [ -n "${CP_INIT_D_PATH}" ]; then
    INIT_D_PATH=$CP_INIT_D_PATH
    mkdir -p $CP_INIT_D_PATH
fi
if [ -n "${CP_USR_SBIN_PATH}" ]; then
    USR_SBIN_PATH=$CP_USR_SBIN_PATH
    mkdir -p $CP_USR_SBIN_PATH
    export PATH=$PATH:$CP_USR_SBIN_PATH
fi


while true; do
    if [ "$1" = "--arm32_openwrt" ]; then
        var_arch="arm"
        var_arch_flag="--arm32_openwrt"
    elif [ "$1" = "--wlpOrchestration" ]; then
        is_wlp_orchestration="true"
        ORCHESTRATION_EXE_SOURCE_PATH="./bin/wlpStandalone"
    elif [ "$1" = "--arm32_rpi" ]; then
        var_arch="arm"
        var_arch_flag="--arm32_rpi"
    elif [ "$1" = "--install" ]; then
        RUN_MODE="install"
    elif [ "$1" = "--egg-install" ]; then
        EGG_MODE=true
    elif [ "$1" = "--uninstall" ]; then
       RUN_MODE="uninstall"
    elif [ "$1" = "--pre_install_test" ]; then
        RUN_MODE="pre_install_test"
    elif [ "$1" = "--post_install_test" ]; then
        RUN_MODE="post_install_test"
    elif [ "$1" = "--token" ]; then
        shift
        OTP_TOKEN=$1
    elif [ "$1" = "--email" ]; then
        shift
        var_email=$1
    elif [ "$1" = "--server" ]; then
        shift
        var_server=$1
    elif [ "$1" = "--offline_mode" ]; then
        var_offline_mode=true
        var_orchestration_mode="offline_mode"
    elif [ "$1" = "--hybrid_mode" ]; then
        var_hybrid_mode=true
        var_orchestration_mode="hybrid_mode"
    elif [ "$1" = "--container_mode" ]; then
        var_container_mode=true
    elif [ "$1" = "--no_otp" ]; then
        var_no_otp=true
    elif [ "$1" = "--fog" ]; then
        shift
        var_fog_address=$1
    elif [ "$1" = "--max-log-size-kb" ]; then
        shift
        WATCHDOG_MAX_FILE_SIZE=$1
    elif [ "$1" = "--max-log-rotation" ]; then
        shift
        WATCHDOG_MAX_ROTATIONS=$1
    elif [ "$1" = "--certs-dir" ]; then
        shift
        var_certs_dir=$1
    elif [ "$1" = "--public-key" ]; then
        shift
        var_public_key=$1
    elif [ "$1" = "--ignore" ]; then
        shift
        ignore_packages=$1
    elif [ "$1" = "--support_practices" ]; then
        shift
        support_practices=$1
    elif [ "$1" = "-ia" ]; then
        ignore_access=accessControl
    elif [ "$1" = "--additional_flags" ]; then
        shift
        var_additional_flags=$1
    elif [ "$1" = "--proxy" ]; then
        shift
        var_proxy=$1
        verify_proxy_config
    elif [ "$1" = "--compact_mode" ]; then
        var_compact_mode=true
    elif [ "$1" = "--filesystem_path" ]; then
        shift
        var=$1
        last_char=${var##${var%%?}}
        echo $var
        if [ "$last_char" = "/" ]; then
            FILESYSTEM_PATH=${var%?}
        else
            FILESYSTEM_PATH=$1
        fi
        echo "Filesystem paths: ${FILESYSTEM_PATH}"
    elif [ "$1" = "--log_files_path" ]; then
        shift
        var=$1
        last_char=${var##${var%%?}}
        echo $var
        if [ "$last_char" = "/" ]; then
            LOG_FILE_PATH=${var%?}
        else
            LOG_FILE_PATH=$1
        fi
        echo "Log files path: ${LOG_FILE_PATH}"
    elif [ "$1" = "--arm64_trustbox" ] || [ "$1" = "--arm64_linaro" ] || [ "$1" = "--arm32_rpi" ] || [ "$1" = "--gaia" ] || [ "$1" = "--smb_mrv_v1" ] || [ "$1" = "--smb_sve_v2" ] || [ "$1" = "--smb_thx_v3" ] || [ "$1" = "--x86" ] || [ "$1" = "./orchestration_package.sh" ]; then
        shift
		continue
    elif [ "$1" = "--skip_registration" ]; then
        var_skip_registration=true
    elif echo "$1" | grep -q ${FORCE_CLEAN_FLAG}; then
        var_upgrade_mode=
    elif echo "$1" | grep -q ${DEBUG_FLAG}; then
        var_installation_debug_mode=true
    elif [ -z "$1" ]; then
        break
    elif [ "$1" = "--debug_on" ] || [ "$1" = "--debug-on" ]; then
        echo "Ignoring deprecated installation flag '$1'"
    else
        echo "Warning: unsupported option '$1'"
    fi
    shift
done

if [ "$RUN_MODE" = "install" ] && [ $var_offline_mode = false ]; then
    if [ -n "$OTP_TOKEN" ] && [ -z "$var_token" ] && [ "$var_no_otp" = "false" ]; then
        var_token=$OTP_TOKEN
        if [ -z "$var_fog_address" ]; then
            gem_prefix="cp-"
            gem_prefix_uppercase="CP-"
            us_prefix="cp-us-"
            us_prefix_uppercase="CP-US-"
            au_prefix="cp-au-"
            au_prefix_uppercase="CP-AU-"
            in_prefix="cp-in-"
            in_prefix_uppercase="CP-IN-"

            if [ "${var_token#"$us_prefix"}" != "${var_token}" ] || [ "${var_token#"$us_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_us_fog_address"
            elif [ "${var_token#$au_prefix}" != "${var_token}" ] || [ "${var_token#"$au_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_au_fog_address"
            elif [ "${var_token#$in_prefix}" != "${var_token}" ] || [ "${var_token#"$in_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_in_fog_address"
            elif [ "${var_token#"$gem_prefix"}" != "${var_token}" ] || [ "${var_token#"$gem_prefix_uppercase"}" != "${var_token}" ]; then
                var_fog_address="$var_default_gem_fog_address"
            else
                echo "Failed to get fog address from token: ${var_token} - check if token is legal"
            fi
        fi
    fi
    if [ $var_hybrid_mode = true ] && [ -z "$var_fog_address" ]; then
        var_fog_address="$var_default_gem_fog_address"
    fi

    if [ -n "$var_proxy" ]; then
        if [ "$var_proxy" = 'none' ]; then
            echo "Ignoring system proxy"
        else
            echo "Proxy='$var_proxy'"
        fi
    fi
    echo "Fog address='${var_fog_address}'"
fi

if command -v which &>/dev/null; then
    var_which_cmd_exists=1
fi

if [ $var_arch != "gaia" ] && [ $var_which_cmd_exists -eq 1 ]; then
    if [ -n "$(which systemctl)" ]; then
        var_startup_service="systemd"
    else
        var_startup_service="upstart"
    fi
fi

cp_print()
{
    if [ "$var_installation_debug_mode" = "true" ] || { [ -n "$2" ] && [ "$2" = "true" ]; }; then
        printf "%b\n" "$1"
    fi
    if [ "$is_smb" != "1" ]; then
        printf "%b\n" "$1" >> ${LOG_FILE_PATH}/${LOG_PATH}/${INSTALLATION_LOG_FILE}
    else
        printf "%b\n" "$1" > ${LOG_FILE_PATH}/${LOG_PATH}/${INSTALLATION_LOG_FILE}
    fi
}

cp_exec()
{
    var_cmd=$1
    var_std_out=$2
    # Send exec output to RES
    RES=$($var_cmd 2>&1)
    if [ -n "$RES" ]; then
        cp_print "$RES" "$var_std_out"
    fi
}

export INSTALL_COMMAND
is_install="$(command -v install)"
if [ -z ${is_install} ]; then
    INSTALL_COMMAND="cp -f"
    cp_print "[WARNING]: install command not found - using cp instead" ${FORCE_STDOUT}
else
    INSTALL_COMMAND=install
fi

cp_copy() # Initials - cc
{
    SRC="$1"
    DEST="$2"
    var_std_out="$3"
    status=
    SRC_MD5=
    DEST_MD5=
    DEST_AFTER_COPY=

    SRC_MD5=$(find "$SRC" -maxdepth 1 -type f -exec md5sum {} \; 2>&1)
    status=$?
    if ! [ $status -eq 0 ]; then SRC_MD5="source '${SRC}' does not exist."; fi

    DEST_MD5=$(find "$DEST" -maxdepth 1 -type f -exec md5sum {} \; 2>&1)
    status=$?
    if ! [ $status -eq 0 ]; then DEST_MD5="destination '${DEST}' does not exist."; fi

    cp_print "Copy source md5:\n$SRC_MD5\nCopy destination md5:\n$DEST_MD5"
    COPY_RETURN_VAL=$($INSTALL_COMMAND "$SRC" "$DEST" 2>&1)
    status=$?
    if ! [ $status -eq 0 ]; then
        cp_print "Error copying: $COPY_RETURN_VAL" "$var_std_out"
        exit 1
    fi

    DEST_AFTER_COPY=$(find "$DEST" -maxdepth 1 -type f -exec md5sum {} \; 2>&1)
    status=$?
    if ! [ $status -eq 0 ]; then DEST_AFTER_COPY="destination '${DEST}' does not exist."; fi
    cp_print "Destination md5, after the copy:\n$DEST_AFTER_COPY"
}

update_cloudguard_appsec_manifest()
{
    if [ -z ${CLOUDGUARD_APPSEC_STANDALONE} ] || [ -z ${DOCKER_RPM_ENABLED} ]; then
        return
    fi

    selected_cloudguard_appsec_manifest_path="/tmp/cloudguard_appsec_manifest.json"
    if [ "${DOCKER_RPM_ENABLED}" = "false" ]; then
        selected_cloudguard_appsec_manifest_path="/tmp/self_managed_cloudguard_appsec_manifest.json"
    fi

    if [ ! -f "$selected_cloudguard_appsec_manifest_path" ]; then
        return
    fi

    cloudguard_appsec_manifest_path="${selected_cloudguard_appsec_manifest_path}.used"
    mv "$selected_cloudguard_appsec_manifest_path" "$cloudguard_appsec_manifest_path"
    fog_host=$(echo "$var_fog_address" | sed 's/https\?:\/\///')
    fog_host=${fog_host%/}
    sed "s/namespace/${fog_host}/g" ${cloudguard_appsec_manifest_path} > "${FILESYSTEM_PATH}/${CONF_PATH}/manifest.json"
}

install_watchdog_gaia()
{
    # verify that DB is clean from cp-nano-watchdog
    tellpm cp-nano-watchdog
    dbset process:cp-nano-watchdog
    dbset process:cp-nano-watchdog:path
    dbset process:cp-nano-watchdog:arg:1
    dbset process:cp-nano-watchdog:runlevel
    # Add cp-nano-watchdog to DB
    dbset process:cp-nano-watchdog t
    dbset process:cp-nano-watchdog:path ${FILESYSTEM_PATH}/${WATCHDOG_PATH}
    dbset process:cp-nano-watchdog:arg:1 --gaia
    dbset process:cp-nano-watchdog:runlevel 1
    dbset :save
    tellpm cp-nano-watchdog t
}

install_watchdog()
{
    # Check if watchdog is updated/new
    old_cp_nano_watchdog_md5=""
    new_cp_nano_watchdog_md5=$(md5sum watchdog/watchdog | awk '{print$1}')
    if [ -f ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog ]; then
        old_cp_nano_watchdog_md5=$(md5sum ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog | awk '{print$1}')
    fi
    if [ "$old_cp_nano_watchdog_md5" = "$new_cp_nano_watchdog_md5" ]; then
        # Watchdog did not changed
        cp_print "There is no update in watchdog. Everything is up to date."
        return
    fi
    cp_print "Installing the watchdog" ${FORCE_STDOUT}

    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${WATCHDOG_PATH}"
    cp_copy watchdog/watchdog ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog
    cp_copy watchdog/wait-for-networking-inspection-modules.sh ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/wait-for-networking-inspection-modules.sh
    cp_exec "chmod 700  ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog"
    cp_exec "chmod 700  ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/wait-for-networking-inspection-modules.sh"
    cp_exec "touch ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/wd.services"
    cp_exec "${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog --register ${FILESYSTEM_PATH}/${SERVICE_PATH}/cp-nano-orchestration $var_arch_flag"
    if [ "$IS_K8S_ENV" = "true" ]; then
        cp_exec "${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog --register ${FILESYSTEM_PATH}/${SERVICE_PATH}/k8s-check-update-listener.sh"
    fi

    cp_print "Install cp-nano-agent service file"

    if [ $var_arch = "arm" ]; then
        cp_print "Install for init.d"
        cp_copy service/arm32_openwrt/nano_agent.init $INIT_D_PATH/nano_agent.init
        cp_exec "chmod +x $INIT_D_PATH/nano_agent.init"
        cp_exec "ln -s $INIT_D_PATH/nano_agent.init /etc/rc.d/S99nano_agent"
    elif [ "$is_smb" = "1" ]; then
        mkdir -p /storage/nano_agent/etc
        cp_copy service/smb/nano_agent.init /storage/nano_agent/etc/nano_agent.init
        chmod +rx /storage/nano_agent/etc/nano_agent.init
    elif [ $var_container_mode = false ]; then
        if [ $var_arch = "gaia" ]; then
            cp_exec "ln -s ${FWDIR}/bin/curl_cli ${FWDIR}/bin/curl"
            cp_exec "ln -s ${CPDIR}/bin/cpopenssl ${CPDIR}/bin/openssl"
            cp_copy watchdog/access_pre_init $INIT_D_PATH/access_pre_init
            chkconfig --add $INIT_D_PATH/access_pre_init
            install_watchdog_gaia
        elif [ "$is_smb" = "1" ]; then
            cp_exec "ln -s ${FWDIR}/bin/curl_cli ${FWDIR}/bin/curl"
            cp_exec "ln -s ${CPDIR}/bin/cpopenssl ${CPDIR}/bin/openssl"
        elif [ $var_startup_service = "systemd" ]; then
            cp_print "Install for systemd"
            cp_copy service/x86/ubuntu16/nano_agent.service /etc/systemd/system/nano_agent.service
            echo "ExecStart=${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog" >> /etc/systemd/system/nano_agent.service
            echo "ExecStartPost=${FILESYSTEM_PATH}/${WATCHDOG_PATH}/wait-for-networking-inspection-modules.sh" >> /etc/systemd/system/nano_agent.service
			echo "Environment=\"FILESYSTEM_PATH=${FILESYSTEM_PATH}\"" >> /etc/systemd/system/nano_agent.service

            cp_exec "systemctl daemon-reload"
            cp_exec "systemctl enable nano_agent"
        else
            cp_print "Install for init.d"
            cp_copy service/x86/ubuntu14/nano_agent.conf /etc/init/nano_agent.conf
            cp_copy service/x86/ubuntu14/nano_agent.init $INIT_D_PATH/nano_agent
            cp_exec "chmod +x $INIT_D_PATH/nano_agent"
            cp_exec "update-rc.d nano_agent defaults"
            cp_exec "update-rc.d nano_agent enable"
        fi
    fi

    if [ -n "${var_upgrade_mode}" ]; then
        touch ${FILESYSTEM_PATH}/${SERVICE_PATH}/restart_watchdog
        cp_print "Restart cp-nano-agent service" ${FORCE_STDOUT}
    else
        cp_print "Start cp-nano-agent service" ${FORCE_STDOUT}
        if [ $var_arch = "arm" ]; then
            cp_exec "$INIT_D_PATH/nano_agent.init start"
        elif [ "$is_smb" = "1" ]; then
            cp_exec "/storage/nano_agent/etc/nano_agent.init start"
        elif [ $var_arch = "gaia" ]; then
            install_watchdog_gaia
        else
            cp_exec "service nano_agent start"
        fi
    fi
}

if [ -f ${FILESYSTEM_PATH}/${CONF_PATH}/${ORCHESTRATION_NAME}/${ORCHESTRATION_NAME}.policy ]; then
    var_upgrade_mode=true
fi

upgrade_orchestration_policy()
{
    # This function help with upgrading the new orchestration policy syntax
    # Updating sleep-interval to pulling-interval
    sed -i "s/sleep/pulling/g" ${FILESYSTEM_PATH}/${CONF_PATH}/${ORCHESTRATION_NAME}/${ORCHESTRATION_NAME}.policy
    sed -i "s/sleep/pulling/g" ${FILESYSTEM_PATH}/${CONF_PATH}/${ORCHESTRATION_NAME}/${ORCHESTRATION_NAME}.policy
}

add_uninstall_script()
{
    cp_exec "cp -f $AGENT_UNINSTALL ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/$AGENT_UNINSTALL"
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/$AGENT_UNINSTALL"
}

install_cp_nano_ctl()
{
    CP_NANO_AGENT_CTL="cp-nano-agent-ctl.sh"
    CP_NANO_CTL_DEPRECATED="cp-ctl"
    CP_NANO_AGENT_CTL_DEPRECATED="cp-nano-agent-ctl-deprecated.sh"
    CP_NANO_CLI="cp-nano-cli.sh"
    CP_NANO_JSON="cpnano_json"
    CP_NANO_CTL="cpnano"
    OPEN_APPSEC_CTL="open-appsec-ctl"
    CP_NANO_YQ_LOCATION="./scripts/yq"
    CP_NANO_YQ="yq"

    if [ -f $USR_SBIN_PATH/${CP_NANO_CTL_DEPRECATED} ]; then
        cp_exec "rm -rf $USR_SBIN_PATH/${CP_NANO_CTL_DEPRECATED}"
    fi
    # Removing old CP-CTL
    if [ -f ${FILESYSTEM_PATH}/${CONF_PATH}/CP_NANO_AGENT_CTL ]; then
        cp_exec "rm -rf ${FILESYSTEM_PATH}/${CONF_PATH}/$CP_NANO_AGENT_CTL"
    fi

    if [ -f ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_NANO_AGENT_CTL_DEPRECATED} ]; then
        cp_exec "rm -f ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_NANO_AGENT_CTL_DEPRECATED} $USR_SBIN_PATH/${CP_NANO_CTL_DEPRECATED}"
    fi

    cp_exec "cp -f $CP_NANO_CLI ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/$CP_NANO_AGENT_CTL"
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/$CP_NANO_AGENT_CTL"

    cp_exec "ln -s ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/$CP_NANO_AGENT_CTL $USR_SBIN_PATH/${CP_NANO_CTL}"
    cp_exec "ln -s ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${OPEN_APPSEC_CTL}.sh $USR_SBIN_PATH/${OPEN_APPSEC_CTL}"

    cp_exec "cp -f ${CP_NANO_DEBUG} ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_NANO_DEBUG}"
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_NANO_DEBUG}"

    cp_exec "cp -f ./cpnano_json ${FILESYSTEM_PATH}/${BIN_PATH}/$CP_NANO_JSON" ${FORCE_STDOUT}
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${BIN_PATH}/$CP_NANO_JSON"

    cp_exec "cp -f ${CP_NANO_BASE64} ${FILESYSTEM_PATH}/${BIN_PATH}/${CP_NANO_BASE64}" ${FORCE_STDOUT}
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${BIN_PATH}/${CP_NANO_BASE64}"

    cp_exec "cp -f ${CP_NANO_YQ_LOCATION} ${FILESYSTEM_PATH}/${BIN_PATH}/${CP_NANO_YQ}" ${FORCE_STDOUT}
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${BIN_PATH}/${CP_NANO_YQ}"
}

set_conf_temp_location()
{
    if [ -n "${CP_ENV_FILESYSTEM}" ]; then
        prefix_filesystem=$(echo $CP_ENV_FILESYSTEM | sed 's|\(.*\)/.*|\1|')
        temp_location=$prefix_filesystem/temp/orchestration_download
        escaped_temp_location=$(echo $temp_location | sed -e 's/\//\\\//g')

        mkdir -p $temp_location
        if ! cat ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE} | grep -q "\"orchestration\":"; then
            sed -i -e "1 s/{/{\n\"orchestration\": {\"Default file download path\": [{\"value\":\""${escaped_temp_location}"\"}]},/" ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
        else
            sed -i -e "/\"orchestration\"/ s/\"orchestration\".*:.*{/\"orchestration\":{\"Default file download path\": [{\"value\":\""${escaped_temp_location}"\"}],/" ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
        fi
    fi
}

set_conf_additional_flags()
{
    if [ -z "$var_additional_flags" ] || cat ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE} | grep -q '\"additional flags\"'; then
        return
    fi
    var_additional_flags="\"$(echo "$var_additional_flags" | sed 's/,/\",\"/g')\""
    if ! cat ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE} | grep -q "\"orchestration\":"; then
        sed -i -e "0,/{/ s/{/{\"orchestration\": {\n\"additional flags\": [{\"flags\": [${var_additional_flags}]}]},/" ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
    else
        sed -i -e "0,/\"orchestration\"/ s/\"orchestration\".*:.*{/\"orchestration\": {\n\"additional flags\": [{\"flags\": [${var_additional_flags}]}],/" ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
    fi
}

upgrade_conf_if_needed()
{
    if [ -f ${FILESYSTEM_PATH}/${ORCHESTRATION_DEBUG_CONF_FILE} ]; then
        sed -i "s|STDOUT|${LOG_FILE_PATH}/${DBG_FILE_PATH}|g" ${FILESYSTEM_PATH}/${ORCHESTRATION_DEBUG_CONF_FILE}
    else
        if [ -f ${FILESYSTEM_PATH}/${CONF_PATH}/orchestration_conf.json ]; then
            cp_exec "mv ${FILESYSTEM_PATH}/${CONF_PATH}/orchestration_conf.json ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}"
            cp_exec "chmod 600 ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}"
        fi

        cp_copy configuration/cp-nano-orchestration-debug-conf.json ${FILESYSTEM_PATH}/${ORCHESTRATION_DEBUG_CONF_FILE}
        cp_exec "chmod 600 ${FILESYSTEM_PATH}/${ORCHESTRATION_DEBUG_CONF_FILE}"

        [ -f "${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg" ] && . "${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg"

        previous_mode=$(cat ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg | grep "orchestration-mode" | cut -d = -f 3 | sed 's/"//')
 		if ! [ -z "$previous_mode" ]; then
            var_orchestration_mode=${previous_mode}
        fi

        if [ ${var_orchestration_mode} = "hybrid_mode" ]; then
            save_local_policy_config
        fi

        cp_exec "cp -f configuration/orchestration.cfg ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg"
        execution_flags="execution_flags=\"--orchestration-mode=${var_orchestration_mode}\""
        echo $execution_flags >> ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg
        if [ $var_arch = "gaia" -o "$is_smb" = "1" ]; then
            if [ -z "${gaia_ld_path}" ]; then
                gaia_ld_path="${LD_LIBRARY_PATH}"
            fi
            sed -i '1i gaia_ld_path='"$gaia_ld_path"'' ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg
        fi
    fi

    cp_exec "${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_NANO_DEBUG} --default --service orchestration"

    if [ ! -f "${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}" ]; then
        cp_print "Creating env details file" ${FORCE_STDOUT}
        if [ $var_container_mode = true ]; then
            echo 'IS_CONTAINER_ENV=true' >> "${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}"
        fi
    fi
    if cat ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE} | grep -q '"/agents/log'; then
        sed -i 's|"/agents/log|"/api/v1/agents/events|' ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
    fi

    set_conf_additional_flags
}

copy_orchestration_executable()
{
    cp_print "Copying cp-nano-agent binary file to folder: ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}" $FORCE_STDOUT
    cp_copy "$ORCHESTRATION_EXE_SOURCE_PATH" ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}"
    cp_copy open-appsec-cloud-mgmt ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/open-appsec-cloud-mgmt
    cp_copy open-appsec-cloud-mgmt-k8s ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/open-appsec-cloud-mgmt-k8s
    cp_copy open-appsec-ctl.sh ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/open-appsec-ctl.sh

    if [ $var_hybrid_mode = true ]; then
        if [ -f /ext/appsec/local_policy.yaml ]; then
            cp_exec "ln -s /ext/appsec/local_policy.yaml ${FILESYSTEM_PATH}/${CONF_PATH}/local_policy.yaml"
        else
            cp_copy local-default-policy.yaml ${FILESYSTEM_PATH}/${CONF_PATH}/local_policy.yaml
        fi
    fi
}

copy_k8s_executable()
{
    if [ "$IS_K8S_ENV" = "true" ]; then
        cp -f k8s-check-update-listener.sh ${FILESYSTEM_PATH}/${SERVICE_PATH}/k8s-check-update-listener.sh
	    chmod +x ${FILESYSTEM_PATH}/${SERVICE_PATH}/k8s-check-update-listener.sh
	    cp -f k8s-check-update-trigger.sh ${FILESYSTEM_PATH}/${SERVICE_PATH}/k8s-check-update-trigger.sh
	    chmod +x ${FILESYSTEM_PATH}/${SERVICE_PATH}/k8s-check-update-trigger.sh
    fi
}

copy_nginx_metadata_script()
{
    cp_copy "$NGINX_METADAT_EXTRACTOR_PATH" ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${NGINX_METADDATA_EXTRACTOR_NAME}
    cp_exec "chmod 700 ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${NGINX_METADDATA_EXTRACTOR_NAME}"
    cp_exec "chmod +x ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${NGINX_METADDATA_EXTRACTOR_NAME}"
}

install_public_key()
{
    return
    if [ -f ${FILESYSTEM_PATH}/${CERTS_PATH}/public-key.pem ]; then
        # Public key is already installed
        return
    fi

    fog_address=${var_fog_address}
    if [ -n "${var_upgrade_mode}" ]; then
        # Upgradde - look in policy.json
        fog_address=$(cat ${FILESYSTEM_PATH}/${CONF_PATH}/${SERVICE_PATH}/orchestration.policy)
    fi

    if [ -z ${var_fog_address} ] || echo "${fog_address}" | grep -q "\"fog-address\":\"\""; then
        # Offline mode - exit from function
        return
    fi

    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${CERTS_PATH}"
    cp_copy certificate/cloud-ngen.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/cloud-ngen.pem
    cp_copy certificate/dev-i2.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/dev-i2.pem
    cp_copy certificate/i2.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/i2.pem
    cp_copy certificate/stg-i2.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/stg-i2.pem

    if [ -n "${var_public_key}" ]; then
        if [ -f "${var_public_key}" ]; then
            # Use private public key (in case of SSL inspection)
            ln -sf "${var_public_key}" ${FILESYSTEM_PATH}/${CERTS_PATH}/public-key.pem
            return
        else
            cp_print "Ignoring non existing public key file '${var_public_key}'" ${FORCE_STDOUT}
        fi
    fi

    if echo "$fog_address" | grep -q "cloud.ngen.checkpoint.com"; then
        ln -sf ${FILESYSTEM_PATH}/${CERTS_PATH}/cloud-ngen.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/public-key.pem
    elif echo "$fog_address" | grep -q "dev.i2.checkpoint.com"; then
        ln -sf ${FILESYSTEM_PATH}/${CERTS_PATH}/dev-i2.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/public-key.pem
    elif echo "$fog_address" | grep -q "stg.i2.checkpoint.com"; then
        ln -sf ${FILESYSTEM_PATH}/${CERTS_PATH}/stg-i2.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/public-key.pem
    elif echo "$fog_address" | grep -q "i2.checkpoint.com"; then
        ln -sf ${FILESYSTEM_PATH}/${CERTS_PATH}/i2.pem ${FILESYSTEM_PATH}/${CERTS_PATH}/public-key.pem
    else
        cp_print "Cannot find certificate for $fog_address" ${FORCE_STDOUT}
        exit 1
    fi
}

uninstall_messaging_proxy_if_needed()
{
    messaging_exec_path="${FILESYSTEM_PATH}/packages/messagingProxy/messagingProxy"
    if [ -f ${messaging_exec_path} ]; then
        chmod +x ${messaging_exec_path}
        ${messaging_exec_path} --uninstall
        rm -rf ${FILESYSTEM_PATH}/packages/messagingProxy
    fi
}

install_orchestration()
{
    INSTALLATION_TIME=$(date)
    if [ "$is_smb" != "1" ]; then
        cp_exec "mkdir -p ${USR_LIB_PATH}/cpnano"
    else
        cp_exec "mkdir -p /storage/nano_agent${USR_LIB_PATH}/cpnano"
        cp_exec "ln -sf /storage/nano_agent${USR_LIB_PATH}/cpnano ${USR_LIB_PATH}/cpnano"
        cp_exec "mkdir -p /storage/nano_agent/${FILESYSTEM_PATH}"
        cp_exec "ln -sf /storage/nano_agent/${FILESYSTEM_PATH} ${FILESYSTEM_PATH}"
    fi
    ${INSTALL_COMMAND} lib/*.so* ${USR_LIB_PATH}/cpnano/
    ${INSTALL_COMMAND} lib/boost/*.so* ${USR_LIB_PATH}/cpnano/

    if [ $var_compact_mode = true ]; then
        [ -f /etc/environment ] && . "/etc/environment"
        if [ -z "${CP_ENV_FILESYSTEM}" ] ; then
            echo "CP_ENV_FILESYSTEM=$FILESYSTEM_PATH" >> "/etc/environment"
        fi
        if [ -z "${CP_ENV_LOG_FILE}"] ; then
            echo "CP_ENV_LOG_FILE=$LOG_FILE_PATH" >> "/etc/environment"
        fi
    fi

    if [ -f "$FILESYSTEM_PATH/$CONF_PATH/custom_policy.cfg" ]; then
        cp_exec "rm -f $FILESYSTEM_PATH/$CONF_PATH/custom_policy.cfg"
    fi

    if command -v ldconfig &>/dev/null; then
        cp_exec "ldconfig" ${FORCE_STDOUT}
    fi
    cp_print "Copy cp-agent-info tool"
    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${SCRIPTS_PATH}"
    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${BIN_PATH}"
    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${SERVICE_PATH}"
    cp_exec "cp ./cp-agent-info.sh ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_AGENT_INFO_NAME}"
    cp_exec "chmod +x ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_AGENT_INFO_NAME}"

    cp_print "Copy ${CP_PACKAGE_LIST_NAME}"
    cp_exec "cp ${CP_PACKAGE_LIST_NAME} ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_PACKAGE_LIST_NAME}"
    cp_exec "chmod +x ${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_PACKAGE_LIST_NAME}"

    cp_exec "cp -f EULA.txt ${FILESYSTEM_PATH}/EULA.txt"
    cp_exec "cp -f Licenses-for-Third-Party-Components.txt ${FILESYSTEM_PATH}/Licenses-for-Third-Party-Components.txt"

    install_public_key
    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${CERTS_PATH}"
    if [ -n "$var_upgrade_mode" ]; then
        upgrade_orchestration_policy
        cp_print "\nStarting upgrading of open-appsec Nano Agent [$INSTALLATION_TIME]" ${FORCE_STDOUT}
        install_cp_nano_ctl
        add_uninstall_script
        cp_exec "cp -f certificate/ngen.body.crt ${FILESYSTEM_PATH}/${CERTS_PATH}/fog.pem"

        [ -f "${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg" ] && . "${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg"
        previous_mode=$(cat ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg | grep "orchestration-mode" | cut -d = -f 3 | sed 's/"//')

        if ! [ -z "$previous_mode" ]; then
            var_orchestration_mode=${previous_mode}
        fi

        if [ ${var_orchestration_mode} = "hybrid_mode" ]; then
            save_local_policy_config
        fi

        cp_exec "cp -f configuration/orchestration.cfg ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg"
        execution_flags="execution_flags=\"--orchestration-mode=${var_orchestration_mode}\""
        echo $execution_flags >> ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg
        if [ $var_arch = "gaia" -o "$is_smb" = "1" ]; then
            if [ -z "${gaia_ld_path}" ]; then
                gaia_ld_path="${LD_LIBRARY_PATH}"
            fi
            sed -i '1i gaia_ld_path='"$gaia_ld_path"'' ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg
        fi

        if [ -f "${FILESYSTEM_PATH}/${CONF_PATH}/default_orchestration_flags" ]; then
            rm -f "${FILESYSTEM_PATH}/${CONF_PATH}/default_orchestration_flags"
        fi

        upgrade_conf_if_needed

        install_watchdog
        cp_print "Upgrade to latest"

        uninstall_messaging_proxy_if_needed

        ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog --un-register ${FILESYSTEM_PATH}/${SERVICE_PATH}/cp-nano-orchestration "$var_arch_flag" > /dev/null 2>&1
        if [ "$IS_K8S_ENV" = "true" ]; then
            ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog --un-register ${FILESYSTEM_PATH}/${SERVICE_PATH}/k8s-check-update-listener.sh
        fi

        if [ ! -f ${FILESYSTEM_PATH}/${DEFAULT_SETTINGS_PATH} ]; then
            echo "{\"agentSettings\": []}" >  ${FILESYSTEM_PATH}/${DEFAULT_SETTINGS_PATH}
        fi

        copy_orchestration_executable
        copy_k8s_executable
        copy_nginx_metadata_script

        ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog --register ${FILESYSTEM_PATH}/${SERVICE_PATH}/cp-nano-orchestration $var_arch_flag
        if [ "$IS_K8S_ENV" = "true" ]; then
            ${FILESYSTEM_PATH}/${WATCHDOG_PATH}/cp-nano-watchdog --register ${FILESYSTEM_PATH}/${SERVICE_PATH}/k8s-check-update-listener.sh
        fi

        cp_print "Upgrade completed successfully" ${FORCE_STDOUT}

        if [ -f /etc/systemd/system/nano_agent.service ]; then
            cat "/etc/systemd/system/nano_agent.service" | grep -q "EnvironmentFile=/etc/environment"
            result=$?

            if [ $var_container_mode = false ] && [ $result -eq 0 ]; then
                sed -i "$ d" /etc/systemd/system/nano_agent.service
                echo "EnvironmentFile=/etc/environment" >> /etc/systemd/system/nano_agent.service
                echo >> /etc/systemd/system/nano_agent.service
                cp_exec "systemctl daemon-reload"
                cp_exec "systemctl restart nano_agent"
            fi
        fi
        exit 0
    fi

    cp_print "\nStarting installation of open-appsec Nano Agent [$INSTALLATION_TIME]" ${FORCE_STDOUT}

    cp_exec "rm -rf ${FILESYSTEM_PATH}/${SERVICE_PATH}"
    cp_exec "rm -rf ${FILESYSTEM_PATH}/${WATCHDOG_PATH}"
    if [ -z ${EGG_MODE} ]; then
        cp_exec "rm -rf ${FILESYSTEM_PATH}/${CONF_PATH}"
        cp_exec "rm -rf ${FILESYSTEM_PATH}/${DATA_PATH}"
    fi

    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${SERVICE_PATH}"
    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${CONF_PATH}"
    cp_exec "mkdir -p ${LOG_FILE_PATH}/${LOG_PATH}"
    cp_exec "mkdir -p ${FILESYSTEM_PATH}/${DATA_PATH}"

    update_cloudguard_appsec_manifest

    if [ ! -f ${FILESYSTEM_PATH}/${DEFAULT_SETTINGS_PATH} ]; then
        echo "{\"agentSettings\": []}" >  ${FILESYSTEM_PATH}/${DEFAULT_SETTINGS_PATH}
    fi

    if [ ! -f ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE} ]; then
        cp_print "Creating env details file" ${FORCE_STDOUT}
        if [ $var_container_mode = true ]; then
            echo 'IS_CONTAINER_ENV=true' >> ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}
        fi
        echo "MAX_FILE_SIZE=${WATCHDOG_MAX_FILE_SIZE}" >> ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}
        echo "MAX_ROTATION=${WATCHDOG_MAX_ROTATIONS}" >> ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}

		if [ -n "${FILESYSTEM_PATH}" ]; then
			echo "CP_ENV_FILESYSTEM=${FILESYSTEM_PATH}" >> ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}
		fi
		if [ -n "${LOG_FILE_PATH}" ]; then
			echo "CP_ENV_LOG_FILE=${LOG_FILE_PATH}" >> ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}
		fi
		if [ -n "${USR_LIB_PATH}" ]; then
			echo "CP_USR_LIB_PATH=${USR_LIB_PATH}" >> ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}
		fi
		if [ -n "${INIT_D_PATH}" ]; then
			echo "CP_INIT_D_PATH=${INIT_D_PATH}" >> ${FILESYSTEM_PATH}/${ENV_DETAILS_FILE}
		fi
    fi

    if [ -z "${var_token}" ] && [ ${var_hybrid_mode} = false ] && [ ${var_offline_mode} = false ] && [ -z ${EGG_MODE} ] && [ ${var_no_otp} = false ]; then
        cp_print "Please enter OTP token []:" ${FORCE_STDOUT}
        read -r var_token
        while [ -z "$var_token" ]; do
            cp_print "You must enter OTP token[]:" ${FORCE_STDOUT}
            read -r var_token
        done
    fi

    cp_print "Building the default policy json"
    echo '{"'$ORCHESTRATION_NAME'": { "fog-address":"'$var_fog_address'", ' > ${FILESYSTEM_PATH}/${CONF_PATH}/policy.json
    echo '"pulling-interval":'$var_sleep_interval', ' >> ${FILESYSTEM_PATH}/${CONF_PATH}/policy.json
    echo '"error-pulling-interval":'$var_error_sleep_interval'},' >> ${FILESYSTEM_PATH}/${CONF_PATH}/policy.json
    echo '"registration-data": { "email-address": "'$var_email'", "registered-server": "'$var_server'"}}' >> ${FILESYSTEM_PATH}/${CONF_PATH}/policy.json

    copy_orchestration_executable
    copy_k8s_executable
    copy_nginx_metadata_script

    install_cp_nano_ctl

    if [ ${var_no_otp} = false ]; then
        cp_print "Saving authentication token to file"
        printf '{\n   "registration type": "token",\n   "registration data": "%b"\n}' "$var_token" | ${FILESYSTEM_PATH}/${BIN_PATH}/${CP_NANO_BASE64} -e > ${FILESYSTEM_PATH}/${CONF_PATH}/registration-data.json
    fi

    add_uninstall_script

    if [ $var_offline_mode = true ]; then
        cp_print "Run Orchestration nano service in offline mode" ${FORCE_STDOUT}
    elif [ $var_hybrid_mode = true ]; then
        cp_print "Run Orchestration nano service in hybrid mode" ${FORCE_STDOUT}
        cp_copy certificate/ngen.body.crt ${FILESYSTEM_PATH}/${CERTS_PATH}/fog.pem

        save_local_policy_config
    else
        cp_copy certificate/ngen.body.crt ${FILESYSTEM_PATH}/${CERTS_PATH}/fog.pem
    fi
    cp_exec "chmod 600 ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}"

    cp_copy configuration/cp-nano-orchestration-conf.json ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
    cp_copy configuration/cp-nano-orchestration-debug-conf.json ${FILESYSTEM_PATH}/${ORCHESTRATION_DEBUG_CONF_FILE}
    cp_exec "chmod 600 ${FILESYSTEM_PATH}/${ORCHESTRATION_DEBUG_CONF_FILE}"

    cp_exec "${FILESYSTEM_PATH}/${SCRIPTS_PATH}/${CP_NANO_DEBUG} --default --service orchestration"

    set_conf_additional_flags

    if [ -n "${var_certs_dir}" ]; then
        if [ -d "${var_certs_dir}" ]; then
            if ! cat ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE} | grep -q "\"message\""; then
                sed -i -e "0,/{/ s|{|{\"message\": {\"Trusted CA directory\": [{\"value\": \"${var_certs_dir}\"}]},|" ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
            else
                sed -i -e "0,/\"message\"/ s|\"message\".*:.*{|\"message\": {\"Trusted CA directory\": [{\"value\": \"${var_certs_dir}\"}],|" ${FILESYSTEM_PATH}/${ORCHESTRATION_CONF_FILE}
            fi
        else
            cp_print "Ignoring non existing certs directory '${var_certs_dir}'" ${FORCE_STDOUT}
        fi
    fi

    set_conf_temp_location

    if [ -n "${var_proxy}" ]; then
        {
            echo '{'
            echo  '    "Fog domain": "",'
            echo  '    "Agent ID": "",'
            echo  '    "Fog port": 0,'
            echo  '    "Tenant ID": "",'
            echo  '    "Profile ID": "",'
            echo  '    "Encrypted connection": false,'
            echo  '    "OpenSSL certificates directory": "",'
            echo  '    "Proxy": "'"${var_proxy}"'"'
            echo  '}'
        } >> "${FILESYSTEM_PATH}/${CONF_PATH}/agent_details.json"
    fi

    if [ -n "$ignore_access" ]; then
        if [ -n "$ignore_packages" ]; then
            ignore_packages=${ignore_packages},${ignore_access}
        else
            ignore_packages=${ignore_access}
        fi
    fi

    if [ -n "$support_practices" ]; then
        echo "$support_practices" | tr ',' '\n' >> ${FILESYSTEM_PATH}/${CONF_PATH}/support-practices.txt
    fi

    if [ -n "$ignore_packages" ]; then
        cp_print "The following packages will be ignored: $ignore_packages" ${FORCE_STDOUT}
        echo "$ignore_packages" | tr ',' '\n' >> ${FILESYSTEM_PATH}/${CONF_PATH}/ignore-packages.txt
    fi

    cp_exec "cp -f configuration/orchestration.cfg ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg"

    execution_flags="execution_flags=\"--orchestration-mode=${var_orchestration_mode}\""
    echo $execution_flags >> ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg
    if [ $var_arch = "gaia" -o "$is_smb" = "1" ]; then
        sed -i '1i gaia_ld_path='"$LD_LIBRARY_PATH"'' ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME}.cfg
    fi

    install_watchdog

    cp_print "Note: in order for the agent to remain active and effective it must connect to the Fog/Cloud at least every 45 days" ${FORCE_STDOUT}
    cp_print "open-appsec Orchestration Nano Service installation completed successfully" ${FORCE_STDOUT}

    if [ $var_hybrid_mode = false ] && [ $var_offline_mode = false ] && [ $var_no_otp = false ] && [ $var_skip_registration = false ]; then
        time_sleep=2
        time_out=60
        cp_print "Registering open-appsec Nano Agent to Fog.." ${FORCE_STDOUT}
        until $USR_SBIN_PATH/${CP_NANO_CTL} -s 2> /dev/null | grep -q "Registration status: Succeeded"; do
            time_out=$(( time_out - time_sleep ))
            if [ $time_out -le 0 ]; then
                cp_print "open-appsec Nano Agent registration failed. Failed to register to Fog: $var_fog_address" ${FORCE_STDOUT}
                exit 1
            fi
            sleep ${time_sleep}
        done
        cp_print "open-appsec Nano Agent is registered to $var_fog_address" ${FORCE_STDOUT}
    fi
}

run_pre_install_test()
{
    cp_print "Pre installation tests completed successfully" ${FORCE_STDOUT}
}

run_post_install_test()
{
    if [ $var_is_alpine = false ]; then
        if [ ! -f ${USR_LIB_PATH}/cpnano/libboost_chrono.so* ]; then
            cp_print "Error, libboost_chrono .so file is missing" ${FORCE_STDOUT}
            exit 1
        fi
        if [ ! -f ${USR_LIB_PATH}/cpnano/libboost_context.so* ]; then
            cp_print "Error, libboost_context .so file is missing" ${FORCE_STDOUT}
            exit 1
        fi
        if [ ! -f ${USR_LIB_PATH}/cpnano/libboost_system.so* ]; then
            cp_print "Error, libboost_system .so file is missing" ${FORCE_STDOUT}
            exit 1
        fi
        if [ ! -f ${USR_LIB_PATH}/cpnano/libboost_thread.so* ]; then
            cp_print "Error, libboost_thread .so file is missing" ${FORCE_STDOUT}
            exit 1
        fi
    fi
    if [ ! -f ${FILESYSTEM_PATH}/${SERVICE_PATH}/${ORCHESTRATION_FILE_NAME} ]; then
        cp_print "Error, cp-nano-agent service file is missing" ${FORCE_STDOUT}
        exit 1
    fi

    cp_print "Post installation tests completed successfully" ${FORCE_STDOUT}
}

uninstall_orchestration()
{
    uninstall_script="${FILESYSTEM_PATH}/$SCRIPTS_PATH/$AGENT_UNINSTALL"
    if [ ! -f "$uninstall_script" ]; then
        cp_dir="${FILESYSTEM_PATH}"
        if [ ! -d "$cp_dir" ]; then
            echo "open-appsec Nano Agent is not installed"
            exit 1
        fi
        echo "Failed to uninstall Orchestration Nano Service, uninstall script was not found in: $uninstall_script "
        exit 1
    fi
     cp_exec "${uninstall_script}"
    if test "$?" = "0"; then
        cp_print "open-appsec Nano Agent successfully uninstalled" ${FORCE_STDOUT}
    else
        cp_print "open-appsec Nano Agent failed to uninstall" ${FORCE_STDOUT}
        exit 1
    fi
}

cp_exec "mkdir -p ${LOG_FILE_PATH}/${LOG_PATH}/default_debugs_output"
cp_exec "mkdir -p ${LOG_FILE_PATH}/${LOG_PATH}/trace_export_files"
cp_exec "touch ${LOG_FILE_PATH}/${LOG_PATH}/${INSTALLATION_LOG_FILE}"
if [ "$RUN_MODE" = "install" ]; then
    install_orchestration
elif [ "$RUN_MODE" = "uninstall" ]; then
    uninstall_orchestration
elif [ "$RUN_MODE" = "pre_install_test" ]; then
    run_pre_install_test
elif [ "$RUN_MODE" = "post_install_test" ]; then
    run_post_install_test
else
    usage
    exit 1
fi
exit 0
