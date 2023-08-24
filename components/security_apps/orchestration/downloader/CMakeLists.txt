ADD_DEFINITIONS(-Wno-deprecated-declarations -Dalpine)

add_library(orchestration_downloader curl_client.cc downloader.cc http_client.cc https_client.cc)

#add_subdirectory(downloader_ut)
