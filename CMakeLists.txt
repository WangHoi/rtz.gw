cmake_minimum_required(VERSION 3.10)
project(rtz.gw C ASM)

set(OPENSSL_ROOT_DIR /usr/local/ssl)
#find_package(OpenSSL 1.1 REQUIRED)
set(OPENSSL_INCLUDE_DIRS ${OPENSSL_ROOT_DIR}/include)
find_library(ssl_LIBRARY ssl PATHS ${OPENSSL_ROOT_DIR}/lib NO_DEFAULT_PATH)
find_library(crypto_LIBRARY crypto PATHS ${OPENSSL_ROOT_DIR}/lib NO_DEFAULT_PATH)
set(OPENSSL_LIBRARIES ${ssl_LIBRARY} ${crypto_LIBRARY})

add_subdirectory(3rdparty/cJSON-1.7.10)
#add_subdirectory(3rdparty/libaco-1.2.4)
add_subdirectory(3rdparty/mxml-2.12)

option(RTZ_SERVER_SSL "enable SSL rtz server" OFF)
option(WITH_ASAN "enable address sanitizer" OFF)
option(WITH_TCMALLOC "link with tcmalloc" OFF)

set(rtz_SRCS
#    src/hook/aco_hook_syscall.c
    src/media/sdp.c
    src/media/fmp4_mux.c
    src/media/ps_rtp_demux.c
    src/media/h26x.c
    src/media/flac_util.c
    src/media/codec_types.c
    src/media/g711.c
    src/media/rtp_demux.c
    src/media/rtp_mux.c
	src/net/net_util.c
#    src/net/rtsp_client.c
    src/net/nbuf.c
    src/net/tcp_chan.c
    src/net/udp_chan.c
    src/net/rtmp_types.c
    src/net/rtmp_handshake.c
    src/net/rtmp_server.c
    src/net/monitor_server.c
    src/net/http_types.c
    src/net/http_hooks.c
    src/net/rtz_server.c
    src/net/stun.c
    src/net/ice.c
    src/net/dtls.c
    src/net/dtls-bio.c
    src/net/rtp.c
    src/net/rtcp.c
    src/net/tcp_chan_ssl.c
    src/zk_util.c
	src/cbuf.c
	src/sbuf.c
	src/event_loop.c
    src/cfg_util.c
	src/log.c
	src/main.c
	src/mpsc_queue.c
    src/algo/base64.c
    src/algo/md5.c
    src/algo/sha1.c
    src/algo/hmac_sha1.c
    src/algo/crc32.c
    src/timestamp.c
    src/apierror.c
#    src/rtmp_client.c
	)
add_executable(rtz.gw ${rtz_SRCS})
include_directories(
    /usr/include/apr-1.0
    ${CMAKE_CURRENT_SOURCE_DIR}/src
#    ${aco_INCLUDE_DIRS}
    ${cJSON_INCLUDE_DIRS}
    ${osip2_INCLUDE_DIRS}
    ${exosip_INCLUDE_DIRS}
    ${mxml_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    )
add_definitions(-pthread -D_GNU_SOURCE ${osip2_DEFINITIONS})
if (WITH_ASAN)
    add_definitions(-fsanitize=address)
    target_link_libraries(rtz.gw asan)
endif ()
if (WITH_TCMALLOC)
    target_link_libraries(rtz.gw tcmalloc)
endif ()
if (RTZ_SERVER_SSL)
    add_definitions(-DRTZ_SERVER_SSL=1)
endif ()
find_library(srtp2_LIBRARY srtp2 PATHS /usr/local/lib NO_DEFAULT_PATH)
target_link_libraries(rtz.gw
    zookeeper_mt
	${cJSON_LIBRARIES}
#	${aco_LIBRARIES}
    ${exosip_LIBRARIES}
    ${osip2_LIBRARIES}
    ${mxml_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${srtp2_LIBRARY}
	pthread
    m
    dl
	)

add_executable(test_srv src/test_srv.c
    src/net/tcp_chan.c
    src/net/nbuf.c
    src/net/net_util.c
	src/mpsc_queue.c
	src/cbuf.c
	src/sbuf.c
	src/event_loop.c
	src/event_loop.c
	src/log.c
)
target_link_libraries(test_srv pthread)
add_executable(test_client src/test_client.c
	src/mpsc_queue.c
	src/cbuf.c
	src/sbuf.c
	src/event_loop.c
	src/event_loop.c
	src/log.c
)
target_link_libraries(test_client uv pthread)
