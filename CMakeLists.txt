cmake_minimum_required(VERSION 3.21)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_COMPILER "/usr/bin/g++-15")

project(dpdk_app CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)


# Path to your DPDK build
set(DPDK_DIR "/home/george/gbot/dpdk")
set(DPDK_BUILD "${DPDK_DIR}/build")
set(DPDK_BUILD_DIR "${DPDK_DIR}/build")
set(DPDK_DRIVER_DIR "${DPDK_BUILD_DIR}/drivers")
set(DPDK_LIB_DIR "${DPDK_BUILD_DIR}/lib")
set(DPDK_INCLUDE_DIR "${DPDK_DIR}/lib/eal/include")

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# Include DPDK headers
include_directories(
    ${DPDK_BUILD_DIR}
    ${DPDK_INCLUDE_DIR}
    ${DPDK_DIR}/config
    ${DPDK_DIR}/lib/ethdev
    ${DPDK_DIR}/lib/log
    ${DPDK_DIR}/lib/eal/linux/include
    ${DPDK_DIR}/lib/eal/x86/include
    ${DPDK_DIR}/lib/net
    ${DPDK_DIR}/lib/mbuf
    ${DPDK_DIR}/lib/mempool
    ${DPDK_DIR}/lib/ring
    ${DPDK_DIR}/lib/meter
)

# Link to DPDK static libs

add_executable(dpdk_app src/main.cpp src/config/config.cpp src/dpdk/dpdk.cpp)
add_executable(test src/test.cpp)

target_link_libraries(dpdk_app
    numa
    ${DPDK_BUILD}/lib/librte_eal.a
    ${DPDK_BUILD}/lib/librte_net.a
    ${DPDK_BUILD}/lib/librte_mbuf.a
    ${DPDK_BUILD}/lib/librte_telemetry.a
    ${DPDK_BUILD}/lib/librte_ethdev.a
    ${DPDK_BUILD}/lib/librte_log.a
    ${DPDK_BUILD}/lib/librte_mempool.a
    ${DPDK_BUILD}/lib/librte_kvargs.a
    ${DPDK_BUILD}/lib/librte_ring.a
    ${DPDK_BUILD}/lib/librte_cmdline.a
    ${DPDK_BUILD}/lib/librte_meter.a
    ${DPDK_BUILD}/drivers/librte_bus_vdev.a
    ${DPDK_BUILD}/drivers/librte_net_tap.a
    ${DPDK_BUILD}/drivers/librte_mempool_ring.a
    pthread
    dl
    m
    rt
)

target_link_libraries(test
    numa
    ${DPDK_BUILD}/lib/librte_eal.a
    ${DPDK_BUILD}/lib/librte_net.a
    ${DPDK_BUILD}/lib/librte_mbuf.a
    ${DPDK_BUILD}/lib/librte_telemetry.a
    ${DPDK_BUILD}/lib/librte_ethdev.a
    ${DPDK_BUILD}/lib/librte_log.a
    ${DPDK_BUILD}/lib/librte_mempool.a
    ${DPDK_BUILD}/lib/librte_kvargs.a
    ${DPDK_BUILD}/lib/librte_ring.a
    ${DPDK_BUILD}/lib/librte_cmdline.a
    ${DPDK_BUILD}/lib/librte_meter.a
    ${DPDK_BUILD}/drivers/librte_bus_vdev.a
    ${DPDK_BUILD}/drivers/librte_net_tap.a
    ${DPDK_BUILD}/drivers/librte_mempool_ring.a
    pthread
    dl
    m
    rt
)


#
#target_link_libraries(test PRIVATE
#  numa.a
#  rte_eal.a
#  rte_mbuf.a
#  rte_telemetry.a
#  rte_ethdev.a
#  rte_log.a
#  rte_mempool.a
#  rte_kvargs.a
#  rte_ring.a
#  rte_net.a
#  rte_net_tap.a
#  rte_meter.a
#)
#
#target_link_libraries(dpdk_app PRIVATE
#  rte_eal
#  rte_ethdev
#  rte_log
#  rte_mempool
#  rte_ring
#  rte_net
#  rte_net_tap
#  rte_meter
#  rte_mbuf
#)

target_compile_options(dpdk_app PRIVATE -O3)
target_link_options(dpdk_app PRIVATE
  -static
  -pthread
)
target_link_options(test PRIVATE
  -static
  -pthread
)


file(COPY ${CMAKE_SOURCE_DIR}/src/config/config.txt
     DESTINATION ${CMAKE_BINARY_DIR})
