#!/bin/bash

build()
{
    local part=$1
    local flavor=$2
    local version="$3"
    
    echo "Building something with $part $flavor $version"
    if [[ $1 == "agent" ]]; then
        echo "Building agent for $2 $3"
        $PWD/scripts/build_agent.sh $flavor $version
    fi
}

publish_output()
{
    bash ./scripts/generate_openappsec_versions_report.sh
    local ret_code=$?
    if [[ $ret_code != 0 ]]; then
        echo "publish image: generate version report failed with error $?"
    fi
    exit $ret_code
}

make_latest()
{
    /ngen/builds/agent-build/master/latest/scripts/latest.py
    local ret_code=$?
    if [[ $ret_code != 0 ]]; then
        echo "Make latest failed with error $?"
    fi
    exit $ret_code
}

main()
{ 
    docker rm `docker ps -aq`
    mkdir -p $PWD/output

    if [[ "$2" == "amzn" || "$2" == "opensuse" || "$2" == "alpine"  || "$2" == "rhel" || "$2" == "fedora" ]]; then
        echo "$2 flavor is currently unsupported"
        exit 0
    fi

    local platform_target="$2"

    build "$1" "$2" "$3"

#    if [[ $(find output/${platform_target} -type f -size -1k | wc -l) -ne 0 ]]; then
#        echo "Error! The following artifacts are malformed:"
#        find output/${platform_target} -type f -size -1k
#        exit 1
#    fi

#    if [[ "${CI_BUILD_REF_NAME}" == "dev" || "${CI_BUILD_REF_NAME}" == "master"  || "${CI_BUILD_REF_NAME}" == "release" || "${CI_BUILD_REF_NAME}" == "hotfix-*" ]]; then
#        find output/${platform_target} -name "openappsec-*" | awk -F/ '{system("mkdir -p  "$1"/agent/x86_64/"$2"/"$3"; cp "$0" "$1"/agent/x86_64/"$2"/"$3"/"$5)}'
#        find output/agent/x86_64/${platform_target} -maxdepth 1 -mindepth 1 | sed 's/output.//' | xargs -IXXX /ngen/builds/agent-build/master/latest/scripts/export.py --platform XXX output
#    fi
}

main $1 $2 $3
