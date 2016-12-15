include(ExternalProject)

ExternalProject_Add(iproute2
  PREFIX			.
  URL				${CMAKE_CURRENT_SOURCE_DIR}/iproute2-4.1.1.tar.gz
  BUILD_IN_SOURCE 	1
  PATCH_COMMAND     cp -f ${CMAKE_CURRENT_SOURCE_DIR}/Makefile tc/
  CONFIGURE_COMMAND ./configure
  BUILD_COMMAND     make
  INSTALL_COMMAND   true
)
