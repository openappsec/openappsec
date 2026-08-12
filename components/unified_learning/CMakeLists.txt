link_directories(${CMAKE_BINARY_DIR}/core/shmem_ipc)
link_directories(${CMAKE_BINARY_DIR}/components/security_apps/waap/waap_clib)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../security_apps/waap/include)

add_library(unified_learning_comp
    unified_learning_comp.cc
    AssetIndicatorsSyncUnit.cc
)

target_include_directories(unified_learning_comp PUBLIC include)

target_link_libraries(unified_learning_comp PUBLIC
    shmem_ipc
    hiredis
    UnifiedIndicatorsContainer
    waap_clib
)
