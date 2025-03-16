install(FILES Dockerfile entry.sh install-cp-agent-intelligence-service.sh install-cp-crowdsec-aux.sh self_managed_cloudguard_appsec_manifest.json DESTINATION .)

add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/agent-docker.img
    COMMAND docker build -t agent-docker ${CMAKE_INSTALL_PREFIX}
    COMMAND docker image save agent-docker -o ${CMAKE_INSTALL_PREFIX}/agent-docker.img
)

add_custom_target(docker DEPENDS ${CMAKE_INSTALL_PREFIX}/agent-docker.img)
