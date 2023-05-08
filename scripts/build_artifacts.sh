#!/bin/bash

build_agent()
{
    #echo "Fetching source code for open appsec agent"
    #git clone https://github.com/openappsec/openappsec.git
    #if [[ $? != 0 ]]; then
    #    echo "Failed to clones source code for openappsec agent"
    #    exit 1
    #fi
    cd openappsec

    if [ -z "$(find /usr -name libgtest.*)" ]; then
        echo "Building gtest library"
        if [[ "${linux_dist}" == "ubuntu" ]]; then
            apt-get -qq install google-mock -y
            if [[ $? != 0 ]]; then
                echo "Failed to install google-mock"
                exit 1
            fi
        fi
        cd /usr/src/googletest
        cmake CMakeLists.txt
        if [[ $? != 0 ]]; then
            echo "Failed to run cmake as part of googletest compilation"
            exit 1
        fi
        
        make
        if [[ $? != 0 ]]; then
            echo "Failed to compile google-mock"
            exit 1
        fi

        cp /usr/src/googletest/googlemock/gtest/libgtest.a /usr/lib/libgtest.a
        cp /usr/src/googletest/googlemock/gtest/libgtest_main.a /usr/lib/libgtest_main.a
        cp /usr/src/googletest/googlemock/libgmock.a /usr/lib/libgmock.a
        cd -
    fi

    echo "Building libraries for open appsec agent"
    local var_cmake_ret_code
    if [[ "${linux_dist}" == "centos" ]]; then
        echo "function(add_unit_test ut_name ut_sources use_libs)" > unit_test.cmake
        echo "endfunction(add_unit_test)" >> unit_test.cmake
        sed -i "s|add_subdirectory(cptest)|#add_subdirectory(cptest)|g" core/CMakeLists.txt

        cmake -DCMAKE_INSTALL_PREFIX=build_out -DBoost_LIBRARY_DIRS=/usr/lib64/boost169 -DBOOST_LIBRARYDIR=/usr/lib64/boost169 -DBOOST_INCLUDEDIR=/usr/include/boost169/ -DCMAKE_CXX_FLAGS="-std=gnu++11 -I/usr/include/openssl11/ -L/usr/lib64/openssl11/"
        var_cmake_ret_code=$?
    elif [[ "${linux_dist}" == "rhel" &&  "${dist_ver}" == "8" ]]; then
        cmake -DCMAKE_INSTALL_PREFIX=build_out -DBoost_LIBRARY_DIRS=/usr/lib64/boost169 -DBOOST_LIBRARYDIR=/usr/lib64/boost169 -DBOOST_INCLUDEDIR=/usr/include/boost169/ -DCMAKE_CXX_FLAGS="-L/usr/lib64/boost169/"
        var_cmake_ret_code=$?
    elif [[ "${linux_dist}" == "fedora" ]]; then
        echo "function(add_unit_test ut_name ut_sources use_libs)" > unit_test.cmake
        echo "endfunction(add_unit_test)" >> unit_test.cmake
        sed -i "s|add_subdirectory(cptest)|#add_subdirectory(cptest)|g" core/CMakeLists.txt
        cmake -DCMAKE_INSTALL_PREFIX=build_out .
        var_cmake_ret_code=$?
    else
        cmake -DCMAKE_INSTALL_PREFIX=build_out .
        var_cmake_ret_code=$?
    fi

    if [[ $var_cmake_ret_code != 0 ]]; then
        echo "Failed to run cmake on openappsec agent code"
        exit 1
    fi

    local var_make_success=0
    for ((try=0; try<10; try++)); do
        make -j 8 install && var_make_success=1 && break
    done

    if [[ $var_make_success == 0 ]]; then
        echo "Failed to run cmake on openappsec agent code"
        exit 1
    fi

    echo "Building packages for open appsec agent"
    make package
    if [[ $? != 0 ]]; then
        echo "Failed to package openappsec agent"
        exit 1
    fi

    mkdir openappsec
    cp build_out/install*.sh openappsec/

    echo "Compressing packages for open appsec agent"
    tar -czvf openappsec-${dist_ver}.tar.gz openappsec/
    if [[ $? != 0 ]]; then
        echo "Failed to compress openappsec agent"
        exit 1
    fi

    cd ..
    echo "Saving packagestar for open appsec agent. Path: output/agent/openappsec-${dist_ver}.tar.gz"
    mkdir -p "output/agent"
    cp openappsec/openappsec-${dist_ver}.tar.gz "output/agent/"
}

build_specific_attachment()
{
    local raw_nginx_ver="$1"
    local nginx_ver="$(echo ${raw_nginx_ver} | sed "s|~|-|g" | sed "s| |-|g")"
    cp -R "attachment_source" "attachment_${nginx_ver}"
    if [[ $? != 0 ]]; then
        echo "Failed to copy attachment source code, Error $?"
        exit 1
    fi
    cd "attachment_${nginx_ver}"

    echo "Building libraries for open appsec attachment"

    nginx -V &> /tmp/nginx.ver
    rm -f /tmp/nginx.configure.output
    sed -i -e 's|make|make -j 8|' ./attachments/nginx/ngx_module/nginx_version_configuration.sh
    ./attachments/nginx/ngx_module/nginx_version_configuration.sh --conf /tmp/nginx.ver build_out >> /tmp/nginx.configure.output
    if [[ $? != 0 ]]; then
        echo "Failed to configure attachment source code"
        cat /tmp/nginx.configure.output
        rm -f /tmp/nginx.configure.output
        exit 1
    fi

    sed -i "s|install(TARGETS ngx_module DESTINATION lib)|#install(TARGETS ngx_module DESTINATION lib)|g" docker/CMakeLists.txt
    if [[ "${linux_dist}" == "centos" ]]; then
        cmake -DCMAKE_INSTALL_PREFIX=build_out . -DCMAKE_CXX_FLAGS="-std=gnu++11 -I/usr/include/openssl11/ -L/usr/lib64/openssl11/" -DCMAKE_C_FLAGS="-std=gnu99 -I/usr/include/openssl11/ -L/usr/lib64/openssl11/"
        if [[ $? != 0 ]]; then
            echo "Failed to run cmake on attachment source code"
            exit 1
        fi
    else
        cmake -DCMAKE_INSTALL_PREFIX=build_out .
        if [[ $? != 0 ]]; then
            echo "Failed to run cmake on attachment source code"
            exit 1
        fi
    fi
    make -j 8 install
    if [[ $? != 0 ]]; then
        echo "Failed to run make on attachment source code"
        exit 1
    fi

    mkdir "ngx_module_${nginx_ver}"
    cp build_out/lib/lib*so "ngx_module_${nginx_ver}"/
    tar -czvf "ngx_module_${nginx_ver}.tar.gz" "ngx_module_${nginx_ver}"/
    if [[ $? != 0 ]]; then
        echo "Failed to compress attachment artifacts"
        exit 1
    fi
    cd ..

    mkdir -p "output/attachment"
    cp "attachment_${nginx_ver}"/"ngx_module_${nginx_ver}.tar.gz" "output/attachment"
    rm -rf "attachment_${nginx_ver}"

    if [[ "${linux_dist}" == "rhel" ]]; then
        /usr/bin/yum remove -y "nginx-${raw_nginx_ver}"
    fi
}

nginx_version_comparator()
{
    local ver1_number
    local ver2_number

    IFS='.' read -r -a ver1_numbers  <<< "$1"
    IFS='.' read -r -a ver2_numbers  <<< "$2"

    local IFS=.
    local len1=${#ver1_numbers[@]}
    local len2=${#ver2_numbers[@]}
    max=$(( len1 > len2 ? len1 : len2 ))
    for ((i=0; i<max; i++)); do
        if [[ -z ${ver2_numbers[i]} ]]; then
            ver2_numbers[i]=0
        elif [[ -z ${ver1_numbers[i]} ]]; then
            ver1_numbers[i]=0
        fi
        if [ ${ver1_numbers[i]} -gt ${ver2_numbers[i]} ]; then
            return 1
        elif [ ${ver1_numbers[i]} -lt ${ver2_numbers[i]} ]; then
            return 2
        fi
    done
    return 0
}

is_nginx_version_supported()
{
    local dist_name=$1
    local dist_ver=$2
    local nginx_ver=$3
    MIN_NGINX_VER=1.18.0

    echo "Testing if nginx version supported. Distro: ${dist_name}, Version: ${dist_ver}, Nginx: ${nginx_ver}"
    local is_supported=$(jq '."'$dist_name'"[] | select(."dist-version"=="'$dist_ver'") | ."versions" | contains(["'$nginx_ver'"])' excluded_versions.list)
    if [[ $is_supported == true ]]; then
        return 1
    fi

    local comp
    nginx_version_comparator $MIN_NGINX_VER "$nginx_ver"
    comp=$?
    return "${comp}"
}

install_nginx()
{
    local ver=$1
    local linux_flavor=$2

    echo "Instaling nginx for os: $linux_flavor, nginx ver: $ver"

    if [[ "$linux_flavor" == "centos" || "$linux_flavor" == "rhel" || "$linux_flavor" == "fedora" || "$linux_flavor" == "amzn" ]]; then
        /usr/bin/yum install -y "nginx-$ver"
    elif [[ "$linux_flavor" == "ubuntu" || "$linux_flavor" == "debian" ]]; then
        /usr/bin/apt-get install -y --allow-downgrades "nginx=$ver" -f
    elif [[ "$linux_flavor" == "alpine" ]]; then
        /sbin/apk add "nginx=$ver"
    elif [[ "$linux_flavor" == "opensuse" ]]; then
        /usr/bin/zypper install --oldpackage -y nginx-$ver
    fi

    if [[ $? == 0 ]]; then
        return 0
    fi
    return 1
}

build_attachments()
{
    echo "Starting iteration over nginx list of distroes"

    if [[ "${linux_dist}" == "rhel" &&  "${dist_ver}" == "9" ]] || [[ "${linux_dist}" == "ubuntu" &&  "${dist_ver}" == "jammy" ]]; then
        if [[ "${linux_dist}" == "rhel" ]]; then
            yum remove -y openssl-devel
        else
            apt remove -y libssl-dev
        fi
        git clone https://github.com/openssl/openssl.git -b OpenSSL_1_1_1-stable
        cd openssl
        if [[ "${linux_dist}" == "rhel" ]]; then
            yum install -y perl-FindBin perl-IPC-Cmd
        else
            apt install -y libfindbin-libs-perl
        fi
        if [[ $? != 0 ]]; then
            echo "Failed to install 'perl-FindBin perl-IPC-Cmd'"
            exit 1
        fi
        ./config
        if [[ $? != 0 ]]; then
            echo "Failed to configure openssl"
            exit 1
        fi
        make -j 8
        if [[ $? != 0 ]]; then
            echo "Failed to build openssl code"
            exit 1
        fi
        make install
        if [[ $? != 0 ]]; then
            echo "Failed to install openssl artifacts"
            exit 1
        fi
        cd ..
    fi

    echo "Fetching source code for open appsec attachment"
    git clone https://github.com/openappsec/attachment.git "attachment_source"
    if [[ $? != 0 ]]; then
        echo "Failed to clone attachment source code"
        exit 1
    fi
    local nginx_versions_to_install="NGINX.list"
    while IFS= read -r line; do
        IFS='-'
        read -ra VER <<< "$line"
        is_nginx_version_supported "$linux_dist" "$dist_ver" "${VER[0]}"
        if [[ $? != 1 ]]; then
            echo "*********** Installing NGINX ver=$line ***********"
            install_nginx "$line" $linux_dist
            if [[ $? == 0 ]]; then
                build_specific_attachment "${line}"
            else
                echo ""
                echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                echo "+++++ ERROR: NGINX version isn't supported from the package manager +++++"
                echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
                echo ""
            fi
       fi
    done < "$nginx_versions_to_install"
    rm -rf "attachment_source"
}

build_specific_kong_attachment()
{
    local openresty_ver="$1"
    if [[ -f "output/attachment/attachment_${openresty_ver}" ]]; then
        return
    fi

    cp -R "attachment_source" "attachment_${openresty_ver}"
    if [[ $? != 0 ]]; then
        echo "Failed to copy attachment source code, Error $?"
        exit 1
    fi
    cd "attachment_${openresty_ver}"

    echo "Building libraries for open appsec attachment"

    /usr/local/openresty/nginx/sbin/nginx -V &> /tmp/nginx.ver
    rm -f /tmp/nginx.configure.output
    sed -i -e 's|make|make -j 8|' ./attachments/nginx/ngx_module/nginx_version_configuration.sh
    ./attachments/nginx/ngx_module/nginx_version_configuration.sh --conf /tmp/nginx.ver build_out >> /tmp/nginx.configure.output
    if [[ $? != 0 ]]; then
        echo "Failed to configure attachment source code"
        cat /tmp/nginx.configure.output
        rm -f /tmp/nginx.configure.output
        exit 1
    fi

    sed -i "s|install(TARGETS ngx_module DESTINATION lib)|#install(TARGETS ngx_module DESTINATION lib)|g" docker/CMakeLists.txt
    if [[ "${linux_dist}" == "centos" ]]; then
        cmake -DCMAKE_INSTALL_PREFIX=build_out . -DCMAKE_CXX_FLAGS="-std=gnu++11 -I/usr/include/openssl11/ -L/usr/lib64/openssl11/" -DCMAKE_C_FLAGS="-std=gnu99 -I/usr/include/openssl11/ -L/usr/lib64/openssl11/"
        if [[ $? != 0 ]]; then
            echo "Failed to run cmake on attachment source code"
            exit 1
        fi
    else
        cmake -DCMAKE_INSTALL_PREFIX=build_out .
        if [[ $? != 0 ]]; then
            echo "Failed to run cmake on attachment source code"
            exit 1
        fi
    fi
    make -j 8 install
    if [[ $? != 0 ]]; then
        echo "Failed to run make on attachment source code"
        exit 1
    fi

    mkdir "openresty_${openresty_ver}"
    cp build_out/lib/lib*so "openresty_${openresty_ver}"/
    tar -czvf "openresty_${openresty_ver}.tar.gz" "openresty_${openresty_ver}"/
    if [[ $? != 0 ]]; then
        echo "Failed to compress attachment artifacts"
        exit 1
    fi
    cd ..

    mkdir -p "output/attachment"
    cp "attachment_${openresty_ver}"/"openresty_${openresty_ver}.tar.gz" "output/attachment"
    rm -rf "attachment_${openresty_ver}"
}

install_kong()
{
    local ver=$1
    local linux_flavor=$2
    local dist_version=$3

    echo "Installing kong for os: $linux_flavor, kong ver: $ver"
    if [[ "$linux_flavor" == "ubuntu" || "$linux_flavor" == "debian" ]]; then
        echo "echo \"$ver\" | cut -d"_" -f2 | cut -d"." -f1"
        local gateway_version=$(echo "$ver" | cut -d"_" -f2 | cut -d"." -f1)
        echo "curl -LO \"https://download.konghq.com/gateway-$gateway_version.x-$linux_flavor-$dist_version/pool/all/k/kong-enterprise-edition/$ver\""
        curl -LO "https://download.konghq.com/gateway-$gateway_version.x-$linux_flavor-$dist_version/pool/all/k/kong-enterprise-edition/$ver"
        echo "dpkg -i --force-confnew \"$ver\""
        dpkg -i --force-confnew "$ver"
    elif [[ "$linux_flavor" == "centos" ]]; then
        echo "echo \"$ver\" | cut -d"-" -f4 | cut -d"." -f1"
        local gateway_version=$(echo "$ver" | cut -d"-" -f4 | cut -d"." -f1)
        echo "curl -LO \"https://download.konghq.com/gateway-$gateway_version.x-$linux_flavor-$dist_version/Packages/k/$ver\""
        curl -LO "https://download.konghq.com/gateway-$gateway_version.x-$linux_flavor-$dist_version/Packages/k/$ver"
        echo "yum -y install \"$ver\""
        yum -y install "$ver"
    fi

    if [[ $? == 0 ]]; then
        return 0
    fi
    return 1
}

build_kong()
{
    local kong_type=$1
    local kong_version_path=$2

    echo "Fetching source code for open appsec attachment"
    git clone https://github.com/openappsec/attachment.git "attachment_source"
    if [[ $? != 0 ]]; then
        echo "Failed to clone attachment source code"
        exit 1
    fi

    echo "Starting iteration over $kong_type list of distroes"
    local kong_versions_to_install="$kong_version_path"
    while IFS= read -r line; do
        echo "*********** Installing $kong_type ver=$line os=$linux_dist ***********"
        if [[ "$linux_dist" == "ubuntu" || "$linux_dist" == "debian" ]]; then
            echo "/usr/bin/apt-get install -y $kong_type=$line"
            /usr/bin/apt-get install -y $kong_type=$line
        elif [[ "$linux_dist" == "centos" ]]; then
            echo "/usr/bin/yum install -y $kong_type-$line"
            /usr/bin/yum install -y $kong_type-$line
        fi

        if [[ $? == 0 ]]; then
            NGINX_VERSION=$(/usr/local/openresty/nginx/sbin/nginx -v |& cut -d/ -f2)
            build_specific_kong_attachment "$NGINX_VERSION"
        else
            echo ""
            echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo "+++++ ERROR: $kong_type version isn't supported from the package manager +++++"
            echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo ""
        fi

        if [[ "$linux_dist" == "ubuntu" || "$linux_dist" == "debian" ]]; then
            /usr/bin/apt-get remove -y $kong_type
        elif [[ "$linux_dist" == "centos" ]]; then
            /usr/bin/yum remove -y $kong_type
        fi
    done < "$kong_versions_to_install"
    rm -rf "attachment_source"
}

if [[ "${package}" == "agent" ]]; then
    build_agent
elif [[ "${package}" == "attachments" ]]; then
    build_attachments
elif [[ "${package}" == "kong" ]]; then
    build_kong kong KONG.list
    build_kong kong-enterprise-edition KONG-ENTERPRISE.list
else 
    echo "Failed to pick agent/attachments/kong to build"
fi

