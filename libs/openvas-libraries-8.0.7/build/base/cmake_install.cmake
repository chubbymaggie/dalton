# Install script for directory: /media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base

# Set the install prefix
IF(NOT DEFINED CMAKE_INSTALL_PREFIX)
  SET(CMAKE_INSTALL_PREFIX "/usr/local")
ENDIF(NOT DEFINED CMAKE_INSTALL_PREFIX)
STRING(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
IF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  IF(BUILD_TYPE)
    STRING(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  ELSE(BUILD_TYPE)
    SET(CMAKE_INSTALL_CONFIG_NAME "Debug")
  ENDIF(BUILD_TYPE)
  MESSAGE(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
ENDIF(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)

# Set the component getting installed.
IF(NOT CMAKE_INSTALL_COMPONENT)
  IF(COMPONENT)
    MESSAGE(STATUS "Install component: \"${COMPONENT}\"")
    SET(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  ELSE(COMPONENT)
    SET(CMAKE_INSTALL_COMPONENT)
  ENDIF(COMPONENT)
ENDIF(NOT CMAKE_INSTALL_COMPONENT)

# Install shared libraries without execute permission?
IF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  SET(CMAKE_INSTALL_SO_NO_EXE "1")
ENDIF(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  FOREACH(file
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_base.so.8.0.7"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_base.so.8"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_base.so"
      )
    IF(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      FILE(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    ENDIF()
  ENDFOREACH()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/lib/libopenvas_base.so.8.0.7;/usr/local/lib/libopenvas_base.so.8;/usr/local/lib/libopenvas_base.so")
  IF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
  IF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
FILE(INSTALL DESTINATION "/usr/local/lib" TYPE SHARED_LIBRARY FILES
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/build/base/libopenvas_base.so.8.0.7"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/build/base/libopenvas_base.so.8"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/build/base/libopenvas_base.so"
    )
  FOREACH(file
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_base.so.8.0.7"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_base.so.8"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_base.so"
      )
    IF(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      FILE(RPATH_REMOVE
           FILE "${file}")
      IF(CMAKE_INSTALL_DO_STRIP)
        EXECUTE_PROCESS(COMMAND "/usr/bin/strip" "${file}")
      ENDIF(CMAKE_INSTALL_DO_STRIP)
    ENDIF()
  ENDFOREACH()
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

IF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/openvas/base/array.h;/usr/local/include/openvas/base/credentials.h;/usr/local/include/openvas/base/openvas_hosts.h;/usr/local/include/openvas/base/cvss.h;/usr/local/include/openvas/base/drop_privileges.h;/usr/local/include/openvas/base/nvticache.h;/usr/local/include/openvas/base/nvti.h;/usr/local/include/openvas/base/settings.h;/usr/local/include/openvas/base/openvas_compress.h;/usr/local/include/openvas/base/openvas_file.h;/usr/local/include/openvas/base/osp.h;/usr/local/include/openvas/base/openvas_networking.h;/usr/local/include/openvas/base/openvas_string.h;/usr/local/include/openvas/base/pidfile.h;/usr/local/include/openvas/base/gpgme_util.h;/usr/local/include/openvas/base/pwpolicy.h")
  IF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
  IF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
FILE(INSTALL DESTINATION "/usr/local/include/openvas/base" TYPE FILE FILES
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/array.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/credentials.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/openvas_hosts.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/cvss.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/drop_privileges.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/nvticache.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/nvti.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/settings.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/openvas_compress.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/openvas_file.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/osp.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/openvas_networking.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/openvas_string.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/pidfile.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/gpgme_util.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/base/pwpolicy.h"
    )
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

