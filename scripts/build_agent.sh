#!/bin/bash

build_image()
{
    local image_name=$1
    local ver=$2
    echo "Build image: docker build -t openappsec-${image_name}:${ver} --network host --build-arg VERSION=${ver} -f scripts/${image_name}/Dockerfile ."
    docker build -t openappsec-"${image_name}":"${ver}" --network host --build-arg VERSION="${ver}" -f "scripts/${image_name}"/Dockerfile .
    local ret_code=$?
    if [[ $ret_code != 0 ]]; then
        echo "Build image: docker build failed with error $?"
        exit $ret_code
    fi
}

build_agent()
{
    local flavor=$1
    local ver=$2
    CI_PROJECT_DIR=$PWD
    echo "oriane"
    echo "${CI_PROJECT_DIR}"
    echo "ROY"
    mkdir -p ${CI_PROJECT_DIR}/output/${flavor}/${ver}
    echo "Run image: docker run --security-opt seccomp=unconfined -e linux_dist="${flavor}" -e dist_ver="${ver}" -e package=agent -v "${CI_PROJECT_DIR}"/output/${flavor}/${ver}/:/output --name openappsec-"${flavor}"-"${ver}"-c -i openappsec-"${flavor}":"${ver}" /build_artifacts.sh"
    docker run --security-opt seccomp=unconfined -e linux_dist="${flavor}" -e dist_ver="${ver}" -e package=agent -v ${PWD}:/openappsec:rw -v "${CI_PROJECT_DIR}"/output/${flavor}/${ver}/:/output --name openappsec-"${flavor}"-"${ver}"-c -i openappsec-"${flavor}":"${ver}" /build_artifacts.sh
    local ret_code=$?
    if [[ $ret_code != 0 ]]; then
        echo "Run image: docker run failed with error $?"
        exit $ret_code
    fi
}

handle_flavor()
{
    local flavor=$1
    shift
    local versions=("$@")
    for ver in "${versions[@]}"; do
        build_image $flavor $ver
        build_agent $flavor $ver
    done
}

handle_flavor $1 $2

