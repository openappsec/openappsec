#!/bin/bash

initializeEnviroment()
{
    TMP_ENCODE=""
    CURRENT_TIME=""
    PACKAGE_VERSION=""
    CUR_NGINX_ALREADY_SUPPORTED=false
    NUMBER_OF_CONFIGURATION_FLAGS=0
    TMP_NGINX_UNPARSED_CONFIGURATION="/tmp/nginx_unparsed_tmp_conf.txt"
    TMP_NGINX_PARSED_CONFIGURATION_FLAGS="/tmp/nginx_parsed_conf_flags.txt"
    TMP_DECODED_FILE_PATH="/tmp/decoded_file.txt"
    IS_ALPINE=false
    if [[ ! -z "$(cat /etc/*release | grep alpine)" ]]; then
        IS_ALPINE=true
    fi

    if [[ $PRODUCT_TYPE == "kong" ]]; then
        SERVER_TYPE="$PRODUCT_TYPE"
        IS_KONG=true
        nginx_cmd=nginx
        if [[ -f $NGINX_INPUT_PATH ]]; then
            nginx_cmd="$NGINX_INPUT_PATH"
        fi
    else
        SERVER_TYPE="nginx"
        IS_KONG=false
        nginx_cmd=nginx
        if [[ -n "$(command -v kong)" ]]; then
            SERVER_TYPE="kong"
            IS_KONG=true
            if [[ -f /usr/local/openresty/nginx/sbin/nginx ]]; then
                nginx_cmd='/usr/local/openresty/nginx/sbin/nginx'
            fi
        fi
    fi
}

usage()
{
    local IS_ERROR=$1
    local option=$2
    if [[ ${IS_ERROR} == true ]]; then
        echo "Error: unsupported option '${option}'"
    fi

    echo "Usage:"
    line_padding="               "
    local debug_print_option="-h, --help"
    printf "%s %s Print (this) help message\n" "$debug_print_option" "${line_padding:${#debug_print_option}}"
    debug_print_option="-d, --debug"
    printf "%s %s Enable debug mode\n" "$debug_print_option" "${line_padding:${#debug_print_option}}"
    debug_print_option="-v, --verbose"
    printf "%s %s show version and configure options\n" "$debug_print_option" "${line_padding:${#debug_print_option}}"
    debug_print_option="-o, --output"
    printf "%s %s change output file name into '${option}'\n" "$debug_print_option" "${line_padding:${#debug_print_option}}"
    debug_print_option="-f, --force"
    printf "%s %s force creation of makefile'\n" "$debug_print_option" "${line_padding:${#debug_print_option}}"

    if [[ ${IS_ERROR} == true ]]; then
        exit -1
    else
        exit 1
    fi
}

debug()
{
    local debug_message=$1
    if [[ $IS_DEBUG_MODE_ACTIVE == true ]]; then
        echo -e $debug_message
    fi
}

check_flags_options()
{
    local argc=$#

    for (( i = 1; i <= $argc; i++ )); do
        local option=${!i}
        local IS_ERROR=false
        if [[ "$option" == "--debug" || "$option" == "-d" ]]; then
            IS_DEBUG_MODE_ACTIVE=true
        elif [[ "$option" == "--verbose" || "$option" == "-v" ]]; then
            IS_VERBOSE_MODE_ACTIVE=true
        elif [[ "$option" == "--force" || "$option" == "-f" ]]; then
            IS_FORCE_OUTPUT=true
        elif [[ "$option" == "--overwrite-file" || "$option" == "-of" ]]; then
            IS_OVERWRITE_FILE=true
        elif [[ "$option" == "--output" || "$option" == "-o" ]]; then
            IS_OUTPUT_NAME_MODE_ACTIVE=true
            i=$((i+1))
            FILE_NAME=${!i}
            if [[ -z ${FILE_NAME} ]]; then
                echo "Error: No file name was given for ${option} option."
                exit -1
            fi
        elif [[ "$option" == "--product" || "$option" == "-p" ]]; then
            i=$((i+1))
            PRODUCT_TYPE=${!i}
            if [[ -z ${PRODUCT_TYPE} ]]; then
                echo "Error: No product name was given for ${option} option."
                exit -1
            fi
        elif [[ "$option" == "--product-version" || "$option" == "-pv" ]]; then
            i=$((i+1))
            PRODUCT_VERSION=${!i}
            if [[ -z ${PRODUCT_VERSION} ]]; then
                echo "Error: No product version was given for ${option} option."
                exit -1
            fi
        elif [[ "$option" == "--product-nginx-path" || "$option" == "-n" ]]; then
            i=$((i+1))
            NGINX_INPUT_PATH=${!i}
            if [[ -z "$NGINX_INPUT_PATH" ]]; then
                echo "Error: No nginx input path was given for ${option} option."
                exit -1
            fi
        elif [[ "$option" == "--help" || "$option" == "-h" ]]; then
            usage ${IS_ERROR} ${option}
        elif [[ ! -z $option ]]; then
            IS_ERROR=true
            usage ${IS_ERROR} ${option}
        fi
    done
}

_main()
{
    echo "Starting verification of Check Point support with local nginx server"
    initializeEnviroment
    getNginxVersion
    ${nginx_cmd} -V &> "$TMP_NGINX_UNPARSED_CONFIGURATION"

    if [[ $IS_VERBOSE_MODE_ACTIVE == true ]]; then
    echo ""
        cat ${TMP_NGINX_UNPARSED_CONFIGURATION}
    echo ""
    fi

    while IFS= read -ra UNPARSED_CONFIGURATION_LINE <&3; do
        if [[ ${UNPARSED_CONFIGURATION_LINE} =~ ^"nginx version:" ]]; then
            openFile
        elif [[ ${UNPARSED_CONFIGURATION_LINE} =~ ^"built by gcc" ]]; then
            addBuiltConfiguration "${UNPARSED_CONFIGURATION_LINE}"
        elif [[ ${UNPARSED_CONFIGURATION_LINE} =~ ^"configure arguments:" ]]; then
            IFS="'"
            addAndCutOptionalFlags ${UNPARSED_CONFIGURATION_LINE}
            IFS=" "
            addRequiredFlags ${CONFIGURATION_FLAGES_NEED_TO_BE_PARSED}
        fi
    done 3<"$TMP_NGINX_UNPARSED_CONFIGURATION"

    if [[ ${COMBINED_CONFIGURATION_FLAGS} =~ "--with-cc="* ]]; then
        PARSED_CONFIGURATION="CONFIGURE_OPT=${COMBINED_CONFIGURATION_FLAGS}"
        NUMBER_OF_CONFIGURATION_FLAGS=$((NUMBER_OF_CONFIGURATION_FLAGS-1))
    else
        PARSED_CONFIGURATION="CONFIGURE_OPT=${BUILT_BY_GCC_FLAG}${COMBINED_CONFIGURATION_FLAGS}"
    fi
    local local_pwd=$(pwd)
    if [[ ${local_pwd:0:2} == "//" ]]; then
        local_pwd=${local_pwd:1}
    fi
    debug "Moving parsed configuration to target ${local_pwd}/${FILE_NAME} configuration file"
    echo -e ${PARSED_CONFIGURATION} > ${FILE_NAME}

    add_nginx_and_release_versions
    if [[ $IS_FORCE_OUTPUT != true ]]; then
        checkFile
    fi
    if [[ $CUR_NGINX_ALREADY_SUPPORTED == true ]]; then
        tearDown
        echo -e "Check Point Nano Agent already supported on this environment"
    else
        tearDown
        echo -e "Extracted environment data to $(pwd)/${FILE_NAME} \nPlease send file to nano-agent-attachments-support@checkpoint.com"
        fi
}

tearDown()
{
    rm -f ${TMP_NGINX_UNPARSED_CONFIGURATION}
    rm -f ${TMP_NGINX_PARSED_CONFIGURATION_FLAGS}
    rm -f ${TMP_DECODED_FILE_PATH}
    rm -f ${TMP_NGINX_VERSION_FILE}
}

getNginxVersion()
{
    TMP_NGINX_VERSION_FILE="/tmp/nginx_version_file.txt"
    ${nginx_cmd} -v &> "$TMP_NGINX_VERSION_FILE"

    while IFS= read -ra UNPARSED_VERSION_CONFIGURATION_LINE <&3; do
        if [[ ${UNPARSED_VERSION_CONFIGURATION_LINE} =~ ^"nginx version:" ]]; then
            if [[ $IS_ALPINE == true ]]; then
                NGINX_VERSION=`echo ${UNPARSED_VERSION_CONFIGURATION_LINE} | grep -oE [0-9]+.[0-9]+.[0-9]+`
            else
                NGINX_VERSION=`echo ${UNPARSED_VERSION_CONFIGURATION_LINE} | grep -oP [0-9]+.[0-9]+.[0-9]+`
            fi
        fi

    done 3<"$TMP_NGINX_VERSION_FILE"

    if [[ ${SERVER_TYPE} == "kong" ]]; then
        if [[ -z ${PRODUCT_VERSION} ]]; then
            KONG_VERSION="$(echo $(kong version) | cut -d" " -f3)"
        else
            KONG_VERSION="$PRODUCT_VERSION"
        fi
    fi
}

openFile()
{
    if [[ ${IS_OUTPUT_NAME_MODE_ACTIVE} != true ]]; then
        if [ ${SERVER_TYPE} == "kong" ]; then
            FILE_NAME="${SERVER_TYPE}_${NGINX_VERSION}.mk"
        else
            FILE_NAME="${NGINX_VERSION}.mk"
        fi
        debug "Trying to create an empty ${NGINX_VERSION} file"
        FILE_NAME_PATH="$(pwd)/${FILE_NAME}"

        if [[ -z ${FILE_NAME_PATH} || ! ( ${FILE_NAME} =~ [0-9]+.[0-9]+.[0-9]+.mk ) ]]; then
            echo "ERROR: can't find nginx version."
            exit -1
        fi

        if [[ -f "${FILE_NAME_PATH}" ]]; then
            if [[ ${IS_OVERWRITE_FILE} != true ]]; then
                echo "The output file: ${FILE_NAME} already exists. Do you want to overwrite this file? [y/N]"
                read answer
                if [[ ${answer} != "y" ]]; then
                    echo -e "Stopping after the operation was cancelled.\nIf you wish to use other output file name you can use option -o or --output"
                    exit -1
                fi
            fi
        fi
    else
        debug "Trying to create an empty ${FILE_NAME} file"
        FILE_NAME_PATH="${FILE_NAME}"
    fi

    touch ${FILE_NAME_PATH} &> /dev/null
    if [ ! -e ${FILE_NAME_PATH} ];then
        echo "Failed to create ${FILE_NAME_PATH}"
        exit -1
    fi
    debug "Created an empty ${FILE_NAME} file"
}

checkFile()
{
    echo -e ${BUILT_BY_GCC_FLAG} > ${TMP_NGINX_PARSED_CONFIGURATION_FLAGS}
    echo -e ${CONFIGURATION_FLAGS} >> ${TMP_NGINX_PARSED_CONFIGURATION_FLAGS}
    echo "$TMP_ENCODE" | base64 --decode > ${TMP_DECODED_FILE_PATH}

    while IFS='|' read -a db_line; do
        local parsed_db_gcc_version=`echo ${db_line[1]} | tr -d -c 0-9`
        local parsed_db_optional_flag=`echo ${db_line[2]}`
        if [[ ${NGINX_VERSION} != ${db_line[0]} ]]; then
            continue
        elif [[ ${GCC_VERSION##*gcc-} != "" ]] && [[ ${GCC_VERSION##*gcc-} !=  ${parsed_db_gcc_version} ]]; then
            continue
        elif [[ ${CC_OPTIONAL_FLAGS} != ${parsed_db_optional_flag} ]]; then
            continue
        else
            if [[ ${GCC_VERSION##*gcc-} == "" ]] && [[ ${db_line[1]} == 5 ]]; then
                NUMBER_OF_CONFIGURATION_FLAGS=$((NUMBER_OF_CONFIGURATION_FLAGS+1))
            fi
            IFS='|'
            checkAllDBLineFlags ${db_line[@]}
            if [[ ${EQUAL_FLAGS} == true ]]; then
                CUR_NGINX_ALREADY_SUPPORTED=true
                break
            fi
        fi
    done < ${TMP_DECODED_FILE_PATH}
}

checkAllDBLineFlags()
{
    local argc=$#
    local argv=("$@")
    local number_of_db_line_flags=$((argc-3))
    local gcc_version_prefix="--with-cc="

    if [[ ${number_of_db_line_flags} == ${NUMBER_OF_CONFIGURATION_FLAGS} ]]; then
        for ((i = 3; i < ${argc}; i++)); do
            if [[ ${argv[i]} =~ ^"${gcc_version_prefix}"* ]]; then
                continue
            fi
            checkFlag ${argv[i]}
            if [[ ${found_equal_flag} == false ]]; then
                EQUAL_FLAGS=false
                return
            fi
        done
    else return
    fi

    EQUAL_FLAGS=true
}

checkFlag()
{
    found_equal_flag=false
    db_flag=$1
    while IFS='\' read -ra flag; do
        if [[ "${flag}" == "${db_flag}" ]] || [[ "${flag} " == "${db_flag}" ]]; then
            found_equal_flag=true
            break
        fi
    done < ${TMP_NGINX_PARSED_CONFIGURATION_FLAGS}
}

addBuiltConfiguration()
{
    BUILT_BY_GCC_FLAG_PREFIX="--with-cc=/usr/bin/"
    if [[ $IS_ALPINE == true ]]; then
        GCC_VERSION=`echo "$1" | grep -oE "gcc "[0-9]+ | tr ' ' '-'`
    else
        GCC_VERSION=`echo "$1" | grep -oP "gcc "[0-9]+ | tr ' ' '-'`
    fi
    if [[ "$GCC_VERSION" == "gcc-4" ]]; then
        GCC_VERSION=gcc-5
    elif [[ "$GCC_VERSION" == "gcc-10" ]] || [[ "$GCC_VERSION" == "gcc-11" ]] || [[ "$GCC_VERSION" == "gcc-12" ]] || [[ "$GCC_VERSION" == "gcc-13" ]]; then
        GCC_VERSION=gcc-8
    fi
    BUILT_BY_GCC_FLAG=" \\\\\n${BUILT_BY_GCC_FLAG_PREFIX}${GCC_VERSION}"
    NUMBER_OF_CONFIGURATION_FLAGS=$((NUMBER_OF_CONFIGURATION_FLAGS+1))
}

addAndCutOptionalFlags()
{
    debug "Parsing all nginx configuration flags"
    CC_EXTRA_PREFIX="EXTRA_CC_OPT="
    CC_OPTIONAL_FLAG_PREFIX="--with-cc-opt="
    LD_OPTIONAL_FLAG_PREFIX="--with-ld-opt="
    local argc=$#
    local argv=("$@")
    for (( i = 0; i < $argc; i++ )); do
        if [[ ${argv[i]} == *"${CC_OPTIONAL_FLAG_PREFIX}"* ]]; then
            debug "Successfully added compilation flags"
            CONFIGURATION_FLAGES_NEED_TO_BE_PARSED="${CONFIGURATION_FLAGES_NEED_TO_BE_PARSED}${argv[i]}"
            i=$((i+1))
            IFS=" "
            addCCFlagsWithoutSpecsLocalFlag ${argv[i]}
            CC_OPTIONAL_FLAGS="${CC_EXTRA_PREFIX}${CC_OPTIONAL_FLAGS}"
        elif [[ ${argv[i]} == *"${LD_OPTIONAL_FLAG_PREFIX}"* ]]; then
            CONFIGURATION_FLAGES_NEED_TO_BE_PARSED="${CONFIGURATION_FLAGES_NEED_TO_BE_PARSED}${argv[i]}"
            i=$((i+1))
        else CONFIGURATION_FLAGES_NEED_TO_BE_PARSED="${CONFIGURATION_FLAGES_NEED_TO_BE_PARSED}${argv[i]}"
        fi
    done
    debug "Successfully finished adding optional flags"
    }

addCCFlagsWithoutSpecsLocalFlag()
{
    local argc=$#
    local argv=("$@")
    SPECS_FLAG_PREFIX="-specs="
    NO_ERROR_PREFIX="-Wno-error="
    FCF_PROTECTION_PREFIX="-fcf-protection"
    FSTACK_PREFIX="-fstack-clash-protection"
    BAZEL_PREFIX="-I/home/runner/.cache/bazel"
    FFILE_PREFIX="-ffile-prefix-map"
    TMP_KONG_INCLUDE="-I/tmp/build/usr/local/kong/include"

    for (( j = 0; j < $argc; j++ )); do
        if [[ ${argv[j]} =~ ^${FFILE_PREFIX} ]] ;
        then
            CC_OPTIONAL_FLAGS="${CC_OPTIONAL_FLAGS} ${FFILE_PREFIX}"
        elif [[ ! ${argv[j]} =~ ^${SPECS_FLAG_PREFIX} ]] && \
        [[ ! ${argv[j]} =~ ^${NO_ERROR_PREFIX} ]] && \
        [[ ! ${argv[j]} =~ ^${FSTACK_PREFIX} ]] && \
        [[ ! ${argv[j]} =~ ^${FCF_PROTECTION_PREFIX} ]] && \
        [[ ! ($IS_KONG == true && ("${argv[j]}" =~ ^${BAZEL_PREFIX})) ]] && \
        [[ ! ($IS_KONG == true && ("${argv[j]}" =~ ^${TMP_KONG_INCLUDE})) ]] ; \
        then
            CC_OPTIONAL_FLAGS="${CC_OPTIONAL_FLAGS} ${argv[j]}"
        fi
    done

    CC_OPTIONAL_FLAGS=`echo $CC_OPTIONAL_FLAGS | grep ^"-"`
}

addRequiredFlags()
{
    local argc=$#
    local argv=("$@")
    CC_OPTIONAL_FLAG_PREFIX="--with-cc-opt="
    LD_OPTIONAL_FLAG_PREFIX="--with-ld-opt="
    ADDITIONAL_MODULE_FLAG_PREFIX="--add-module="
    DYNAMIC_MODULE_FLAG_PREFIX="--add-dynamic-module="
    BUILD_FLAG_PREFIX="--build="
    OPENSSL_VERSION_PREFIX="--with-openssl="
    OPENSSL_OPT_PREFIX="--with-openssl-opt="
    ZLIB_VERSION_PREFIX="--with-zlib="
    HPACK_ENC_PREFIX="--with-http_v2_hpack_enc"
    AUTH_JWT_PREFIX="--with-http_auth_jwt_module"
    F4F_PREFIX="--with-http_f4f_module"
    HLS_PREFIX="--with-http_hls_module"
    SESSION_LOG_PREFIX="--with-http_session_log_module"
    COMMON_PREFIX="--"
    PCRE_PREFIX="--with-pcre="
    PCRE_OPT_PREFIX="--with-pcre-opt="
    NGINX_PATH_PREFIX="--prefix="

    for (( i = 1; i < $argc; i++ )); do
        if [[ "${argv[i]}" =~ ^${COMMON_PREFIX} ]] && \
        [[ ! ("${argv[i]}" =~ ^${CC_OPTIONAL_FLAG_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ^${LD_OPTIONAL_FLAG_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${ADDITIONAL_MODULE_FLAG_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${OPENSSL_VERSION_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${OPENSSL_OPT_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${ZLIB_VERSION_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${DYNAMIC_MODULE_FLAG_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${BUILD_FLAG_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${AUTH_JWT_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${F4F_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${HLS_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${SESSION_LOG_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${PCRE_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${PCRE_OPT_PREFIX}) ]] && \
        [[ ! ("${argv[i]}" =~ ${HPACK_ENC_PREFIX}) ]] && \
        [[ ! ($IS_KONG == true && ("${argv[i]}" =~ ${NGINX_PATH_PREFIX})) ]] ; \
        then
            debug "Adding configuration flag: ${argv[i]}\n"
            NUMBER_OF_CONFIGURATION_FLAGS=$((NUMBER_OF_CONFIGURATION_FLAGS+1))
            CONFIGURATION_FLAGS="${CONFIGURATION_FLAGS} \\\\\n${argv[i]}"
        fi
    done
    COMBINED_CONFIGURATION_FLAGS="${CONFIGURATION_FLAGS}\n\n${CC_OPTIONAL_FLAGS}"
    debug "Successfully added nginx configuration flags"
}

add_nginx_and_release_versions()
{
    echo -e "NGINX_VERSION=${NGINX_VERSION}" >> ${FILE_NAME}
    [ -n "${KONG_VERSION}" ] && echo -e "KONG_VERSION=${KONG_VERSION}" >> "${FILE_NAME}"
    RELEASE_VERSION=`cat /etc/*-release | grep -i "PRETTY_NAME\|Gaia" | cut -d"\"" -f2`
    echo -e "RELEASE_VERSION=${RELEASE_VERSION}" >> ${FILE_NAME}
}

echo -e "Check Point Nano Agent Nginx compatibility verifier version ${PACKAGE_VERSION}\n"
check_flags_options "$@"
initializeEnviroment
_main
