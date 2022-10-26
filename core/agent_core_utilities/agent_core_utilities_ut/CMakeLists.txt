include_directories(${CMAKE_SOURCE_DIR}/cptest/include)

add_unit_test(
	agent_core_utilities_ut
	"agent_core_utilities_ut.cc"
	"agent_core_utilities;shell_cmd;config;time_proxy;-lboost_regex"
)
