# Install script for directory: /media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc

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
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_misc.so.8.0.7"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_misc.so.8"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_misc.so"
      )
    IF(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      FILE(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    ENDIF()
  ENDFOREACH()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/lib/libopenvas_misc.so.8.0.7;/usr/local/lib/libopenvas_misc.so.8;/usr/local/lib/libopenvas_misc.so")
  IF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
  IF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
FILE(INSTALL DESTINATION "/usr/local/lib" TYPE SHARED_LIBRARY FILES
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/build/misc/libopenvas_misc.so.8.0.7"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/build/misc/libopenvas_misc.so.8"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/build/misc/libopenvas_misc.so"
    )
  FOREACH(file
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_misc.so.8.0.7"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_misc.so.8"
      "$ENV{DESTDIR}/usr/local/lib/libopenvas_misc.so"
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
   "/usr/local/include/openvas/misc/arglists.h;/usr/local/include/openvas/misc/bpf_share.h;/usr/local/include/openvas/misc/ftp_funcs.h;/usr/local/include/openvas/misc/kb.h;/usr/local/include/openvas/misc/network.h;/usr/local/include/openvas/misc/pcap_openvas.h;/usr/local/include/openvas/misc/plugutils.h;/usr/local/include/openvas/misc/popen.h;/usr/local/include/openvas/misc/openvas_proctitle.h;/usr/local/include/openvas/misc/openvas_auth.h;/usr/local/include/openvas/misc/openvas_logging.h;/usr/local/include/openvas/misc/openvas_server.h;/usr/local/include/openvas/misc/openvas_uuid.h;/usr/local/include/openvas/misc/prefs.h;/usr/local/include/openvas/misc/nvt_categories.h;/usr/local/include/openvas/misc/internal_com.h;/usr/local/include/openvas/misc/www_funcs.h;/usr/local/include/openvas/misc/radius.h")
  IF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
  IF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  ENDIF (CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
FILE(INSTALL DESTINATION "/usr/local/include/openvas/misc" TYPE FILE FILES
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/arglists.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/bpf_share.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/ftp_funcs.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/kb.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/network.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/pcap_openvas.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/plugutils.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/popen.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/openvas_proctitle.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/openvas_auth.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/openvas_logging.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/openvas_server.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/openvas_uuid.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/prefs.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/nvt_categories.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/internal_com.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/www_funcs.h"
    "/media/snouto/rest/projects/dalton/libs/openvas-libraries-8.0.7/misc/radius.h"
    )
ENDIF(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")

