cmake_minimum_required(VERSION 3.10)

set(BUILD_NUMBER CACHE STRING "The number of the current build.")

if ("${BUILD_NUMBER}" STREQUAL "")
	set(BUILD_NUMBER "0")
endif()

project("SoftEther VPN"
		VERSION "5.01.${BUILD_NUMBER}"
		LANGUAGES C
		)

include(tools.cmake)
include(openssl.cmake)
include(ncurses.cmake)
include(readline.cmake)
include(iconv.cmake)
include(sodium.cmake)

set(TOP_DIRECTORY SoftEtherVPN)

# Date and time
string(TIMESTAMP DATE_DAY "%d" UTC)
string(TIMESTAMP DATE_MONTH "%m" UTC)
string(TIMESTAMP DATE_YEAR "%Y" UTC)
string(TIMESTAMP TIME_HOUR "%H" UTC)
string(TIMESTAMP TIME_MINUTE "%M" UTC)
string(TIMESTAMP TIME_SECOND "%S" UTC)

message(STATUS "Build date: ${DATE_DAY}/${DATE_MONTH}/${DATE_YEAR}")
message(STATUS "Build time: ${TIME_HOUR}:${TIME_MINUTE}:${TIME_SECOND}")

add_definitions(-D_REENTRANT -DREENTRANT
		-D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64
		-DNDEBUG -DVPN_SPEED -DUNIX -DOS_UNIX -DUNIX_LINUX)

## building cedar
set(cedar_srcs
		Account.c
		Admin.c
		AzureClient.c
		Bridge.c
		BridgeUnix.c
		BridgeWin32.c
		Cedar.c
		Client.c
		CM.c
		Command.c
		Connection.c
		Console.c
		Database.c
		DDNS.c
		EM.c
		EtherLog.c
		Hub.c
		IPC.c
		Layer3.c
		Link.c
		Listener.c
		Logging.c
		Nat.c
		NativeStack.c
		NM.c
		NullLan.c
		Proto.c
		Protocol.c
		Proto_EtherIP.c
		Proto_IKE.c
		Proto_IkePacket.c
		Proto_IPsec.c
		Proto_L2TP.c
		Proto_OpenVPN.c
		Proto_PPP.c
		Proto_SSTP.c
		Proto_Win7.c
		Proto_WireGuard.c
		Radius.c
		Remote.c
		Sam.c
		SecureNAT.c
		SeLowUser.c
		Server.c
		Session.c
		SM.c
		SW.c
		UdpAccel.c
		UT.c
		Virtual.c
		VLanUnix.c
		VLanWin32.c
		WaterMark.c
		WebUI.c
		WinUi.c
		Wpc.c
		../../3rdparty/BLAKE2/ref/blake2s-ref.c)

PREPEND(cedar_srcs_with_path "${TOP_DIRECTORY}/src/Cedar" ${cedar_srcs})

add_library(cedar ${cedar_srcs_with_path})
target_compile_definitions(cedar PRIVATE
		-DCEDAR_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
		-DCEDAR_VERSION_MINOR=${PROJECT_VERSION_MINOR}
		-DCEDAR_VERSION_BUILD=${PROJECT_VERSION_PATCH}
		-DBUILDER_NAME="$ENV{USER}")

target_include_directories(cedar PRIVATE
		"include/"
		"${TOP_DIRECTORY}/src"
		"${TOP_DIRECTORY}/src/Cedar"
		"libsodium/src/libsodium/include"
		"${TOP_DIRECTORY}/3rdparty/BLAKE2/ref")

target_compile_options(cedar PRIVATE -fPIE -fsigned-char -O2)
target_link_libraries(cedar PRIVATE readline ncurses sodium)

## building mayaqua
set(mayaqua_srcs
		Cfg.c
		DNS.c
		Encrypt.c
		FileIO.c
		HTTP.c
		Internat.c
		Kernel.c
		Mayaqua.c
		Memory.c
		Network.c
		Object.c
		OS.c
		Pack.c
		Proxy.c
		Secure.c
		Str.c
		Table.c
		TcpIp.c
		Tick64.c
		Tracking.c
		Unix.c
		../../../include/ifaddrs.c)

PREPEND(mayaqua_srcs_with_path "${TOP_DIRECTORY}/src/Mayaqua" ${mayaqua_srcs})
add_library(mayaqua ${mayaqua_srcs_with_path})

target_link_libraries(mayaqua PRIVATE ssl crypto z iconv)
target_compile_definitions(mayaqua PRIVATE -DSKIP_CPU_FEATURES)
target_compile_options(mayaqua PRIVATE -fPIE -fsigned-char -O2)
target_include_directories(mayaqua PRIVATE "include/" "${TOP_DIRECTORY}/src" "${TOP_DIRECTORY}/src/Mayaqua")

# Build libhamcore
#set(hamcore_srcs
#		FileSystem.c
#		Hamcore.c
#		Memory.c)
#
#PREPEND(hamcore_srcs_with_path "${TOP_DIRECTORY}/src/libhamcore" ${hamcore_srcs})
#add_library(hamcore ${hamcore_srcs_with_path})
#target_include_directories(hamcore PRIVATE
#		"include/"
#		"${TOP_DIRECTORY}/src"
#		"${TOP_DIRECTORY}/src/libhamcore")
#
#target_link_libraries(hamcore PRIVATE z)

# build hamcorebuilder
#add_executable(hamcorebuilder ${TOP_DIRECTORY}/src/hamcorebuilder/main.c)
#
#target_include_directories(hamcorebuilder PRIVATE
#		"include/"
#		"${TOP_DIRECTORY}/src"
#		"${TOP_DIRECTORY}/src/hamcorebuilder"
#		"${TOP_DIRECTORY}/src/libhamcore"
#		"${TOP_DIRECTORY}/3rdparty/tinydir")
#
#target_link_libraries(hamcorebuilder PRIVATE libhamcore)
#target_compile_options(hamcorebuilder PRIVATE -fPIE -fsigned-char -O2)

# build vpnclient
add_executable(vpnclient ${TOP_DIRECTORY}/src/vpnclient/vpncsvc.c)
target_compile_options(vpnclient PRIVATE -fPIE -fsigned-char -O2)
target_include_directories(vpnclient PRIVATE
		"include/"
		"${TOP_DIRECTORY}/src")

target_link_libraries(vpnclient cedar mayaqua)

# build vpncmd
add_executable(vpncmd ${TOP_DIRECTORY}/src/vpncmd/vpncmd.c)
target_compile_options(vpncmd PRIVATE -fPIE -fsigned-char -O2)
target_include_directories(vpncmd PRIVATE
		"include/"
		"${TOP_DIRECTORY}/src")
target_link_libraries(vpncmd cedar mayaqua)

# post build
set(SOFTETHER_ASSET_DIR ${CMAKE_SOURCE_DIR}/../../../build/sevpnassets/${ANDROID_ABI})

add_custom_target(makeassetdir ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SOFTETHER_ASSET_DIR})

#add_custom_command(TARGET hamcorebuilder POST_BUILD
#  COMMAND
#  ${CMAKE_COMMAND} -E copy
#  ${CMAKE_CURRENT_BINARY_DIR}/hamcorebuilder
#  ${SOFTETHER_ASSET_DIR}
#)


add_custom_command(TARGET vpncmd POST_BUILD
  COMMAND
  ${CMAKE_COMMAND} -E copy
  ${CMAKE_CURRENT_BINARY_DIR}/vpncmd
  ${SOFTETHER_ASSET_DIR}
)

add_custom_command(TARGET vpnclient POST_BUILD
  COMMAND
  ${CMAKE_COMMAND} -E copy
  ${CMAKE_CURRENT_BINARY_DIR}/vpnclient
  ${SOFTETHER_ASSET_DIR}
)

# add_dependencies(hamcorebuilder makeassetdir)
add_dependencies(vpncmd makeassetdir)
add_dependencies(vpnclient makeassetdir)