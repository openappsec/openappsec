add_subdirectory(package)

gen_package(
	install-cp-nano-agent-cache.sh
	agent_cache
	./install-cp-nano-agent-cache.sh
	Check Point Cache Nano Service Version ${PACKAGE_VERSION} Install Package
)
