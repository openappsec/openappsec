add_subdirectory(cpnano_base64)

ADD_DEFINITIONS(-Wno-deprecated-declarations)

add_library(encryptor encryptor.cc "cpnano_base64/base64.cc")

add_subdirectory(encryptor_ut)
