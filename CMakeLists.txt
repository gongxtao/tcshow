cmake_minimum_required (VERSION 2.8)

project (netnsAgent)

set(CMAKE_VERBOSE_MAKEFILE true)

set(CMAKE_BUILD_TYPE "RelWithDebInfo")
# set(CMAKE_BUILD_TYPE "Debug")
message(STATUS "BUILD_TYPE=${CMAKE_BUILD_TYPE}, SVN_REVISION=${SVN_REVISION}, BUILD_NUMBER=${BUILD_NUMBER}")
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE)

add_subdirectory(tc)
include_directories(${CMAKE_BINARY_DIR}/tc/src/iproute2/include)
include_directories(${CMAKE_BINARY_DIR}/tc/src/iproute2/tc)
link_directories(${CMAKE_BINARY_DIR}/tc/src/iproute2/lib)
link_directories(${CMAKE_BINARY_DIR}/tc/src/iproute2/tc)
                   
# set(CMAKE_C_FLAGS        "${CMAKE_C_FLAGS_${BUILD_TYPE}}       -m64 -march=native -pthread -std=gnu99")
# set(CMAKE_C_LINK_FLAGS   "${CMAKE_C_LINK_FLAGS}                -m64 -march=native -Wl,-melf_x86_64 -pthread ")

# set(CMAKE_C_FLAGS        "${CMAKE_C_FLAGS}   -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wnested-externs -Wcast-qual -Wformat-security -Wundef -Wwrite-strings -Wno-error=unused-but-set-variable -Wno-strict-aliasing")

include_directories(src)
aux_source_directory(src ${PROJECT_NAME}_SOURCES)
add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SOURCES})
add_dependencies(${PROJECT_NAME} iproute2)
#target_link_libraries(${PROJECT_NAME} -Wl,-whole-archive tc_impl -Wl,-no-whole-archive tc util netlink m dl)
target_link_libraries(${PROJECT_NAME} -Wl,-whole-archive tc_impl -Wl,-no-whole-archive tc util netlink m dl)

set(CMAKE_INSTALL_PREFIX "/opt/unet")

execute_process(
  COMMAND bash -c "git describe 2> /dev/null || echo `git rev-parse --short HEAD`"
  OUTPUT_VARIABLE PROJECT_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(CPACK_PACKAGE_NAME                      "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION                   "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY       "ULB Layer 4")
set(CPACK_PACKAGE_CONTACT                   "leo.xu@ucloud.cn")

set(CPACK_PACKAGING_INSTALL_PREFIX          "${CMAKE_INSTALL_PREFIX}")

SET(CPACK_GENERATOR                         "RPM")
set(CPACK_SYSTEM_NAME                       "x86_64")
set(CPACK_RPM_PACKAGE_ARCHITECTURE          "x86_64")
set(CPACK_RPM_PACKAGE_REQUIRES              "libnl-devel")
set(CPACK_RPM_SPEC_INSTALL_POST             "/bin/true")

include(CPack)
