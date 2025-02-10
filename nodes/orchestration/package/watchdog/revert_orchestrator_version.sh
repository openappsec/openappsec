#!/bin/sh

SCRIPT_FOLDER=$(dirname "$0")
PARENT_FOLDER=$(dirname "$SCRIPT_FOLDER")
FILESYSTEM_PATH=$PARENT_FOLDER
UPGRADE_STATUS_FILE=${FILESYSTEM_PATH}/revert/upgrade_status
FORBIDDEN_VERSIONS_FILE=${FILESYSTEM_PATH}/revert/forbidden_versions
LAST_KNOWN_WORKING_ORCHESTRATOR=${FILESYSTEM_PATH}/revert/last_known_working_orchestrator
LOG_FILE=$1
CONFIG_FILE="${FILESYSTEM_PATH}/conf/cp-nano-orchestration-conf.json"

get_configuration_with_default()
{
    section="$1"
    key="$2"
    default_value="$3"

    local value
    value=$(awk -v section="$section" -v k="$key" -v def_value="$default_value" '
        BEGIN {
        found_section=0;
        found_key=0;
        }
        $0 ~ "\"" section "\"" { found_section=1; next; }
        found_section && $0 ~ "\"" k "\"" {
        found_key=1;
        next;
        }
        found_key && $0 ~ /"value"/ {
        match($0, /"value"[[:space:]]*:[[:space:]]*"?([^",}]*)"?/, arr);
        if (arr[1] != "")
            print arr[1];
        exit;
        }
        found_section && $0 ~ /^\}/ { found_section=0; found_key=0; }
        END {
        if (!found_key) print def_value;
        }
    ' "$CONFIG_FILE")

    echo "$value"
}

log()
{
    curr_date_time=$(date +%Y-%m-%dT%H:%M:%S)
    callee_function=${1}
    echo "[${curr_date_time}@${callee_function}] ${2}" >>${LOG_FILE}
}

if [ -f "$UPGRADE_STATUS_FILE" ]; then
    awk '{print $2}' "$UPGRADE_STATUS_FILE" >> "$FORBIDDEN_VERSIONS_FILE"
    cp "$UPGRADE_STATUS_FILE" ${FILESYSTEM_PATH}/revert/failed_upgrade_info
fi

if [ -f "$LAST_KNOWN_WORKING_ORCHESTRATOR" ]; then
    manifest_file_path=$(get_configuration_with_default "orchestration" "Manifest file path" "${FILESYSTEM_PATH}/conf/manifest.json")
    cp ${FILESYSTEM_PATH}/revert/last_known_manifest "$manifest_file_path"

    to_version=$(awk '{print $2}' "$UPGRADE_STATUS_FILE")
    last_known_orch_version=$($LAST_KNOWN_WORKING_ORCHESTRATOR --version)
    log "revert_orchestrator_version.sh" "Reverting orchestration version $to_version to last known working orchestrator (version: $last_known_orch_version)"
    installation_flags="--install"

    trusted_ca_directory=$(get_configuration_with_default "message" "Trusted CA directory" "")
    if [ -n "$trusted_ca_directory" ]; then
        installation_flags="${installation_flags} --certs-dir ${trusted_ca_directory}"
    fi
    if grep -q '^CP_VS_ID=' ${FILESYSTEM_PATH}/conf/environment-details.cfg; then
        cp_vs_id=$(grep '^CP_VS_ID=' "$config_file" | cut -d'=' -f2)
        installation_flags="${installation_flags} --vs_id ${cp_vs_id}"
    fi

    chmod +x ${LAST_KNOWN_WORKING_ORCHESTRATOR}
    $LAST_KNOWN_WORKING_ORCHESTRATOR ${installation_flags}
else
    log "revert_orchestrator_version.sh" "Last known working orchestrator not found"
    exit 1
fi
