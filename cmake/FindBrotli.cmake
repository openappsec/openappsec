# FindBrotli.cmake
#
# Supports COMPONENTS:
#   decoder, encoder, common
#
# Exports targets:
#   Brotli::decoder
#   Brotli::encoder
#   Brotli::common
#
# Optional variables:
#   BROTLI_ROOT_DIR
#   BROTLI_USE_STATIC_LIBS

# ------------------------------------------------------------
# Version handling (not supported)
# ------------------------------------------------------------
if(Brotli_FIND_VERSION)
  set(_brotli_version_error_msg "FindBrotli.cmake does not support version checking.")
  if(Brotli_FIND_REQUIRED)
    message(FATAL_ERROR "${_brotli_version_error_msg}")
  elseif(NOT Brotli_FIND_QUIETLY)
    message(WARNING "${_brotli_version_error_msg}")
  endif()
endif()

# ------------------------------------------------------------
# Component dependencies
# ------------------------------------------------------------
if(Brotli_FIND_REQUIRED_decoder OR Brotli_FIND_REQUIRED_encoder)
  set(Brotli_FIND_REQUIRED_common TRUE)
endif()

# ------------------------------------------------------------
# Static library preference
# ------------------------------------------------------------
if(BROTLI_USE_STATIC_LIBS)
  set(_brotli_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
  if(WIN32)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
  else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif()
endif()

# ------------------------------------------------------------
# Optional pkg-config
# ------------------------------------------------------------
find_package(PkgConfig QUIET)

# ------------------------------------------------------------
# Includes
# ------------------------------------------------------------
find_path(Brotli_INCLUDE_DIR
  NAMES
    brotli/decode.h
    brotli/encode.h
  HINTS
    ${BROTLI_ROOT_DIR}
  PATH_SUFFIXES
    include
    includes
)
mark_as_advanced(Brotli_INCLUDE_DIR)

# ------------------------------------------------------------
# Internal state
# ------------------------------------------------------------
set(_brotli_req_vars "")

# For figuring out the real (non-ALIAS) targets when using pkg-config
set(_brotli_decoder_real_target "")
set(_brotli_encoder_real_target "")
set(_brotli_common_real_target "")

if(BROTLI_USE_STATIC_LIBS)
  set(_brotli_stat_str "_STATIC")
else()
  set(_brotli_stat_str "")
endif()

# ------------------------------------------------------------
# Components loop
# ------------------------------------------------------------
foreach(_listvar "common;common" "decoder;dec" "encoder;enc")
  list(GET _listvar 0 _component)
  list(GET _listvar 1 _libname)

  # ---- pkg-config path ----
  if(PKG_CONFIG_FOUND)
    if(BROTLI_USE_STATIC_LIBS)
      pkg_check_modules(
        Brotli_${_component}_STATIC
        QUIET
        GLOBAL
        IMPORTED_TARGET
        libbrotli${_libname}
      )
    else()
      pkg_check_modules(
        Brotli_${_component}
        QUIET
        GLOBAL
        IMPORTED_TARGET
        libbrotli${_libname}
      )
    endif()
  endif()

  # If pkg-config created an imported target, make our alias to it.
  if(TARGET PkgConfig::Brotli_${_component}${_brotli_stat_str})
    add_library(
      Brotli::${_component}
      ALIAS
      PkgConfig::Brotli_${_component}${_brotli_stat_str}
    )

    # Save the underlying real target name for later linkage fixes
    set(_brotli_${_component}_real_target "PkgConfig::Brotli_${_component}${_brotli_stat_str}")

    set(Brotli_${_component}_FOUND TRUE)

    if(Brotli_FIND_REQUIRED_${_component})
      # For FindPackageHandleStandardArgs: ensure libraries are actually present
      if(BROTLI_USE_STATIC_LIBS)
        list(APPEND _brotli_req_vars Brotli_${_component}_STATIC_LIBRARIES)
      else()
        list(APPEND _brotli_req_vars Brotli_${_component}_LINK_LIBRARIES)
      endif()
    endif()

    continue()
  endif()

  # ---- find_library path ----
  if(Brotli_FIND_REQUIRED_${_component})
    list(APPEND _brotli_req_vars Brotli_${_component})
  endif()

  if(BROTLI_USE_STATIC_LIBS)
    set(_brotli_names
      brotli${_libname}-static
      libbrotli${_libname}-static
    )
  else()
    set(_brotli_names
      brotli${_libname}
      libbrotli${_libname}
    )
  endif()

  find_library(Brotli_${_component}
    NAMES ${_brotli_names}
    HINTS ${BROTLI_ROOT_DIR}
    PATH_SUFFIXES
      lib
      lib64
      libs
      libs64
      lib/x86_64-linux-gnu
  )
  mark_as_advanced(Brotli_${_component})

  if(Brotli_${_component})
    set(Brotli_${_component}_FOUND TRUE)

    add_library(Brotli::${_component} UNKNOWN IMPORTED)
    set_target_properties(Brotli::${_component} PROPERTIES
      IMPORTED_LOCATION "${Brotli_${_component}}"
      INTERFACE_INCLUDE_DIRECTORIES "${Brotli_INCLUDE_DIR}"
    )

    # In this branch, our target is real (not ALIAS), so it can be linked later.
    set(_brotli_${_component}_real_target "Brotli::${_component}")
  else()
    set(Brotli_${_component}_FOUND FALSE)
  endif()
endforeach()

# ------------------------------------------------------------
# Link decoder/encoder → common (but never on ALIAS targets or IMPORTED targets)
# ------------------------------------------------------------
if(_brotli_common_real_target)
  foreach(_comp decoder encoder)
    if(_brotli_${_comp}_real_target)
      # Only link if the target is NOT an ALIAS and NOT an IMPORTED target
      get_target_property(_aliased ${_brotli_${_comp}_real_target} ALIASED_TARGET)
      get_target_property(_imported ${_brotli_${_comp}_real_target} IMPORTED)
      if(NOT _aliased AND NOT _imported)
        target_link_libraries(${_brotli_${_comp}_real_target} INTERFACE ${_brotli_common_real_target})
      endif()
    endif()
  endforeach()
endif()

# ------------------------------------------------------------
# Aggregate convenience variables
# ------------------------------------------------------------
set(Brotli_LIBRARIES "")
foreach(_comp decoder encoder common)
  if(TARGET Brotli::${_comp})
    list(APPEND Brotli_LIBRARIES Brotli::${_comp})
  endif()
endforeach()

# ------------------------------------------------------------
# Final package check (FIXED: use _brotli_req_vars)
# ------------------------------------------------------------
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Brotli
  FOUND_VAR
    Brotli_FOUND
  REQUIRED_VARS
    Brotli_INCLUDE_DIR
    ${_brotli_req_vars}
  HANDLE_COMPONENTS
)

# ------------------------------------------------------------
# Restore suffixes
# ------------------------------------------------------------
if(BROTLI_USE_STATIC_LIBS)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${_brotli_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES})
endif()


