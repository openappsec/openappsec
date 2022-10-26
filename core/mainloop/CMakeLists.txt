if("${PLATFORM_TYPE}" STREQUAL  "arm32_openwrt")
    ADD_DEFINITIONS(-Wno-unused-parameter)
endif()
add_library(mainloop mainloop.cc coroutine.cc)

add_subdirectory(mainloop_ut)
