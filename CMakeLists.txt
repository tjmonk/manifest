cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(manifest
	VERSION 0.1
    DESCRIPTION "Manifest Generator"
)

find_package(OpenSSL REQUIRED)

set(MANIFEST_SOURCES )
list(APPEND MANIFEST_SOURCES src/manifest.c)

if( ${OPENSSL_VERSION} VERSION_LESS 3 )
	message("Using OpenSSL 1.x")
	list(APPEND MANIFEST_SOURCES src/ssl1.c)
else()
	message("Using OpenSSL 3.x")
	list(APPEND MANIFEST_SOURCES src/ssl3.c)
endif()

add_executable( ${PROJECT_NAME}
	${MANIFEST_SOURCES}
)

target_include_directories( ${PROJECT_NAME}
	PRIVATE inc
)

target_link_libraries( ${PROJECT_NAME}
	${CMAKE_THREAD_LIBS_INIT}
	rt
	crypto
	tjson
	varserver
)

install(TARGETS ${PROJECT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
