#!/bin/bash

LC_ALL=C

initializeEnvironment()
{
    if [ "$IS_FILE_PATH_PROVIDED" != YES ]; then
        FILE_NAME_PATH=
        IS_FILE_PATH_PROVIDED=NO
    fi

    TMP_NGINX_VERSION_FILE="/tmp/nginx_version_file.txt"
    if [ "$IS_CONFIG_FILE_PROVIDED" != YES ]; then
        TMP_NGINX_CONFIG_FILE="/tmp/nginx_config_file.txt"
        IS_CONFIG_FILE_PROVIDED=NO
    fi

    SERVER_TYPE="nginx"
    nginx_cmd=nginx

    NGX_CC_OPT=
    NGX_LD_OPT=

    USE_PCRE=NO

    TEST_BUILD_EPOLL=NO
    USE_THREADS=NO

    HTTP_V3=NO
    HTTP_SSL=NO

    HTTP_GZIP=YES
    HTTP_GUNZIP=NO
    HTTP_GZIP_STATIC=NO

    HTTP_PROXY=YES
    HTTP_GEOIP=NO
    HTTP_GEO=YES

    HTTP_REALIP=NO
    HTTP_DAV=NO
    HTTP_CACHE=YES
    HTTP_UPSTREAM_ZONE=YES
    NGX_COMPAT=NO
    GCC_VERSION=

    NGINX_VERSION=
    RELEASE_VERSION=

    for i in {0..34}; do
        var_name="NGX_MODULE_SIGNATURE_${i}"
        eval $var_name=0
    done
}

extract_nginx_version_and_release()
{
    ${nginx_cmd} -v &> "$TMP_NGINX_VERSION_FILE"
    NGINX_VERSION=`cat "$TMP_NGINX_VERSION_FILE" | grep -oP [0-9]+.[0-9]+.[0-9]+`
    RELEASE_VERSION=`cat /etc/*-release | grep -i "PRETTY_NAME\|Gaia" | cut -d"\"" -f2`
}

tearDown()
{
    rm -f ${TMP_NGINX_VERSION_FILE}
    rm -f ${TMP_NGINX_CONFIG_FILE}
}

filter_cc_opt() {
    CC_OPT=
    for cc_extra_opt in ${@}; do
        if [[ ${cc_extra_opt} =~ ^-ffile-prefix-map ]]; then
            echo "removing ${cc_extra_opt}"
            continue
        fi
        if [[ ${cc_extra_opt} =~ ^-fdebug-prefix-map ]]; then
            echo "removing ${cc_extra_opt}"
            continue
        fi

        if [ -z "$CC_OPT" ]; then
            CC_OPT="${cc_extra_opt}"
        else
            CC_OPT="${CC_OPT} ${cc_extra_opt}"
        fi
    done

    if [[ "$@" != "${CC_OPT}" ]]; then
        echo "Notice: reduced CC_OPT is '${CC_OPT}'"
    fi

    NGX_CC_OPT="${CC_OPT}"
}

extract_gcc()
{
    GCC_VERSION=`echo "$1" | grep -oP "gcc "[0-9]+ | tr ' ' '-'`
    if [[ "$GCC_VERSION" == "gcc-4" ]]; then
        GCC_VERSION=gcc-5
    elif [[ "$GCC_VERSION" == "gcc-10" ]] || [[ "$GCC_VERSION" == "gcc-11" ]] || [[ "$GCC_VERSION" == "gcc-12" ]] || [[ "$GCC_VERSION" == "gcc-13" ]]; then
        GCC_VERSION=gcc-8
    fi
}

extract_cc_opt_ld_opt() {
    local loc_options="$1"
    NGX_CC_OPT=$(echo "$loc_options" | sed -n "s/.*--with-cc-opt='\([^']*\)'.*/\1/p")

    filter_cc_opt "$NGX_CC_OPT"

    NGX_CC_OPT="$NGX_CC_OPT" 
    NGX_LD_OPT=$(echo "$loc_options" | sed -n "s/.*--with-ld-opt='\([^']*\)'.*/\1/p")
    if [ -n "$NGX_LD_OPT" ]; then
        NGX_LD_OPT="$NGX_LD_OPT"
    fi
}

read_config_flags() {
    for option; do
        opt="$opt `echo $option | sed -e \"s/\(--[^=]*=\)\(.* .*\)/\1'\2'/\"`"

        case "$option" in
            -*=*) value=`echo "$option" | sed -e 's/[-_a-zA-Z0-9]*=//'` ;;
            *) value="" ;;
        esac

        case "$option" in
            --with-http_realip_module)           HTTP_REALIP=YES            ;;
            --with-http_dav_module)              HTTP_DAV=YES               ;;
            --with-compat)                       NGX_COMPAT=YES             ;;
            --without-http-cache)                HTTP_CACHE=NO              ;;
            --without-http_upstream_zone_module) HTTP_UPSTREAM_ZONE=NO      ;;
            --without-http_geo_module)           HTTP_GEO=NO                ;;
            --with-http_geoip_module)            HTTP_GEOIP=YES             ;;
            --with-http_geoip_module=dynamic)    HTTP_GEOIP=YES             ;;
            --without-http_proxy_module)         HTTP_PROXY=NO              ;;
            --with-http_gunzip_module)           HTTP_GUNZIP=YES            ;;
            --with-http_gzip_static_module)      HTTP_GZIP_STATIC=YES       ;;
            --without-http_gzip_module)          HTTP_GZIP=NO               ;;
            --with-http_v3_module)               HTTP_V3=YES                ;;
            --with-threads)                      USE_THREADS=YES            ;;
            --test-build-epoll)                  TEST_BUILD_EPOLL=YES       ;;
            --with-pcre)                         USE_PCRE=YES               ;;
            --with-http_ssl_module)              HTTP_SSL=YES               ;;
            *)
                # echo "$0: uninteresting option: \"$option\""
            ;;
        esac
    done

    if [ "$NGX_COMPAT" = YES ]; then
        HTTP_GZIP=YES
        HTTP_DAV=NO
        HTTP_REALIP=NO
        HTTP_PROXY=YES
        HTTP_GEOIP=NO
        HTTP_GEO=YES
        HTTP_UPSTREAM_ZONE=YES
        HTTP_GUNZIP=NO
        HTTP_GZIP_STATIC=NO
        HTTP_SSL=NO
        USE_THREADS=NO
    fi
}

decode_configuration_flags() {
    DECODED_CONFIGURATION_FLAGS=""
    if [ -n "$GCC_VERSION" ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-cc=/usr/bin/${GCC_VERSION}"
    fi
    if [ "$HTTP_REALIP" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-http_realip_module"
    fi
    if [ "$HTTP_DAV" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-http_dav_module"
    fi
    if [ "$NGX_COMPAT" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-compat"
    fi
    if [ "$HTTP_CACHE" = NO ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --without-http-cache"
    fi
    if [ "$HTTP_UPSTREAM_ZONE" = NO ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --without-http_upstream_zone_module"
    fi
    if [ "$HTTP_GEO" = NO ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --without-http_geo_module"
    fi
    if [ "$HTTP_GEOIP" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-http_geoip_module --with-http_geoip_module=dynamic"
    fi
    if [ "$HTTP_PROXY" = NO ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --without-http_proxy_module"
    fi
    if [ "$HTTP_GUNZIP" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-http_gunzip_module"
    fi
    if [ "$HTTP_GZIP_STATIC" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-http_gzip_static_module"
    fi
    if [ "$HTTP_GZIP" = NO ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --without-http_gzip_module"
    fi
    if [ "$HTTP_V3" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-http_v3_module"
    fi
    if [ "$USE_THREADS" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-threads"
    fi
    if [ "$TEST_BUILD_EPOLL" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --test-build-epoll"
    fi
    if [ "$USE_PCRE" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-pcre"
    fi
    if [ "$HTTP_SSL" = YES ]; then
        DECODED_CONFIGURATION_FLAGS="$DECODED_CONFIGURATION_FLAGS --with-http_ssl_module"
    fi

    echo "$DECODED_CONFIGURATION_FLAGS"
}

set_signatures() {
    NGX_MODULE_SIGNATURE_9=1
    NGX_MODULE_SIGNATURE_10=1
    NGX_MODULE_SIGNATURE_12=1
    NGX_MODULE_SIGNATURE_17=0
    NGX_MODULE_SIGNATURE_25=1
    NGX_MODULE_SIGNATURE_27=1

    if [ "$USE_PCRE" = YES ]; then
        NGX_MODULE_SIGNATURE_23=1
    fi

    if [ "$TEST_BUILD_EPOLL" = YES ]; then
        NGX_MODULE_SIGNATURE_5=1
        NGX_MODULE_SIGNATURE_6=1
    fi

    if [ "$USE_THREADS" = YES ]; then
        NGX_MODULE_SIGNATURE_22=1
    fi

    if [ "$HTTP_V3" = YES ]; then
        NGX_MODULE_SIGNATURE_18=1
        NGX_MODULE_SIGNATURE_24=1
    fi

    if [ "$HTTP_GUNZIP" = YES ] || [ "$HTTP_GZIP" = YES ] || [ "$HTTP_GZIP_STATIC" = YES ]; then
        NGX_MODULE_SIGNATURE_26=1
    fi

    if [ "$HTTP_REALIP" = YES ]; then
        NGX_MODULE_SIGNATURE_28=1
        NGX_MODULE_SIGNATURE_29=1
    fi

    if [ "$HTTP_DAV" = YES ]; then
        NGX_MODULE_SIGNATURE_31=1
    fi

    if [ "$HTTP_CACHE" = YES ]; then
        NGX_MODULE_SIGNATURE_32=1
    fi

    if [ "$HTTP_UPSTREAM_ZONE" = YES ]; then
        NGX_MODULE_SIGNATURE_33=1
    fi

    if [ "$NGX_COMPAT" = YES ]; then
        NGX_MODULE_SIGNATURE_3=1
        NGX_MODULE_SIGNATURE_4=1
        NGX_MODULE_SIGNATURE_18=1
        NGX_MODULE_SIGNATURE_22=1
        NGX_MODULE_SIGNATURE_24=1
        NGX_MODULE_SIGNATURE_26=1
        NGX_MODULE_SIGNATURE_28=1
        NGX_MODULE_SIGNATURE_29=1
        NGX_MODULE_SIGNATURE_30=1
        NGX_MODULE_SIGNATURE_31=1
        NGX_MODULE_SIGNATURE_33=1
        NGX_MODULE_SIGNATURE_34=1
    fi
}

combine_signatures_into_bash() {
    for i in {0..34}; do
        var_name="NGX_MODULE_SIGNATURE_${i}"
        NGX_SCRIPT_VERIFICATION_DATA="${NGX_SCRIPT_VERIFICATION_DATA}${!var_name}"
    done
}

print_flags() {
    echo "Saving configuration to ${FILE_NAME_PATH}"
    echo -e "NGX_SCRIPT_VERIFICATION_DATA=$NGX_SCRIPT_VERIFICATION_DATA" >> ${FILE_NAME_PATH}
    echo -e "NGX_MODULE_SIGNATURE=$(strings $(which ${nginx_cmd}) | grep -F '8,4,8')" >> ${FILE_NAME_PATH}
    echo -e "USE_PCRE=$USE_PCRE" >> ${FILE_NAME_PATH}
    echo -e "TEST_BUILD_EPOLL=$TEST_BUILD_EPOLL" >> ${FILE_NAME_PATH}
    echo -e "USE_THREADS=$USE_THREADS" >> ${FILE_NAME_PATH}
    echo -e "HTTP_V3=$HTTP_V3" >> ${FILE_NAME_PATH}
    echo -e "HTTP_SSL=$HTTP_SSL" >> ${FILE_NAME_PATH}
    echo -e "HTTP_GZIP=$HTTP_GZIP" >> ${FILE_NAME_PATH}
    echo -e "HTTP_GUNZIP=$HTTP_GUNZIP" >> ${FILE_NAME_PATH}
    echo -e "HTTP_GZIP_STATIC=$HTTP_GZIP_STATIC" >> ${FILE_NAME_PATH}
    echo -e "HTTP_PROXY=$HTTP_PROXY" >> ${FILE_NAME_PATH}
    echo -e "HTTP_GEOIP=$HTTP_GEOIP" >> ${FILE_NAME_PATH}
    echo -e "HTTP_GEO=$HTTP_GEO" >> ${FILE_NAME_PATH}
    echo -e "HTTP_REALIP=$HTTP_REALIP" >> ${FILE_NAME_PATH}
    echo -e "HTTP_DAV=$HTTP_DAV" >> ${FILE_NAME_PATH}
    echo -e "HTTP_CACHE=$HTTP_CACHE" >> ${FILE_NAME_PATH}
    echo -e "HTTP_UPSTREAM_ZONE=$HTTP_UPSTREAM_ZONE" >> ${FILE_NAME_PATH}
    echo -e "NGX_COMPAT=$NGX_COMPAT" >> ${FILE_NAME_PATH}
    echo -e "NGX_CC_OPT=$NGX_CC_OPT" >> ${FILE_NAME_PATH}
    echo -e "NGX_LD_OPT=$NGX_LD_OPT" >> ${FILE_NAME_PATH}
    echo -e "GCC_VERSION=$GCC_VERSION" >> ${FILE_NAME_PATH}
    echo -e "NGINX_VERSION=$NGINX_VERSION" >> ${FILE_NAME_PATH}
    echo -e "RELEASE_VERSION=$RELEASE_VERSION" >> ${FILE_NAME_PATH}
}

save_config() {
    initializeEnvironment
    extract_nginx_version_and_release

    if [ "$IS_FILE_PATH_PROVIDED" = NO ]; then
        FILE_NAME_PATH="$(pwd)/$NGINX_VERSION.mk"
    fi
    rm -f ${FILE_NAME_PATH}

    if [ "$IS_CONFIG_FILE_PROVIDED" = NO ]; then
        ${nginx_cmd} -V &> "$TMP_NGINX_CONFIG_FILE"
    fi
            
    gcc_argument=$(cat $TMP_NGINX_CONFIG_FILE | grep "built by gcc")
    extract_gcc "${gcc_argument}"

    configure_arguments=$(cat $TMP_NGINX_CONFIG_FILE | grep "^configure arguments:" | sed 's/^configure arguments: //')
    extract_cc_opt_ld_opt "$configure_arguments"
    configure_arguments=$(echo "$configure_arguments" | sed "s/--with-cc-opt='[^']*'//" | sed "s/--with-ld-opt='[^']*'//" | tr -s ' ')

    read_config_flags $configure_arguments
    set_signatures
    combine_signatures_into_bash
    print_flags
}

read_chkp_mk_file() {
    input_file="$1"

    if [[ ! -f "$input_file" ]]; then
    echo "Error: File '$input_file' not found."
    exit 1
    fi

    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        if [[ "$line" =~ ^([A-Z_]+)=(.*)$ ]]; then
            var_name="${BASH_REMATCH[1]}"
            var_value="${BASH_REMATCH[2]}"
            export "$var_name"="$var_value"
        fi
    done < "$input_file"
}

print_ngx_config() {
    read_chkp_mk_file "$1"
    decode_configuration_flags
}

parse_save_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config_file)
                if [[ -n "$2" ]]; then
                    TMP_NGINX_CONFIG_FILE="$2"
                    IS_CONFIG_FILE_PROVIDED=YES
                    shift 2
                else
                    echo "Error: --config_file requires a value."
                    exit 1
                fi
                ;;
            --save-location)
                if [[ -n "$2" ]]; then
                    FILE_NAME_PATH="$2"
                    IS_FILE_PATH_PROVIDED=YES
                    shift 2
                else
                    echo "Error: --save-location requires a value."
                    exit 1
                fi
                ;;
            *)
                echo "Error: Invalid argument '$1'."
                echo "Usage: $0 save [--config_file <file_path>] [--save-location <file_path>]"
                exit 1
                ;;
        esac
    done
}

if [[ "$1" == "save" ]]; then
    shift
    parse_save_arguments "$@"
    save_config
elif [[ "$1" == "load" ]]; then
    if [[ -n "$2" ]]; then
        print_ngx_config "$2"
    else
        echo "Error: Missing file path for 'load' command."
        echo "Usage: $0 load <file_path>"
        exit 1
    fi
else
    echo "Error: Invalid command."
    echo "Usage: $0 <save|load> [file_path]"
    exit 1
fi

