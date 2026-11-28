cmake_minimum_required(VERSION 3.21)
project(etherape2026 VERSION 1.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# 6.4 is what Ubuntu 24.04 LTS ships; the CI builds with it so the
# distribution package works on the current LTS without extra repositories.
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Widgets Network)
find_package(Threads REQUIRED)

qt_standard_project_setup()
set(CMAKE_AUTORCC ON)

# ---------------------------------------------------------------------------
# libpcap: pkg-config on POSIX, Npcap SDK on Windows.
# ---------------------------------------------------------------------------
if(WIN32)
    set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}" CACHE PATH "Npcap SDK root")
    if(NOT NPCAP_SDK_DIR)
        set(NPCAP_SDK_DIR "C:/npcap-sdk")
    endif()

    find_path(PCAP_INCLUDE_DIR pcap.h HINTS "${NPCAP_SDK_DIR}/Include")
    find_library(PCAP_LIBRARY NAMES wpcap HINTS "${NPCAP_SDK_DIR}/Lib/x64")
    find_library(PACKET_LIBRARY NAMES Packet HINTS "${NPCAP_SDK_DIR}/Lib/x64")

    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "Npcap SDK not found. Download it from https://npcap.com/dist/ "
            "and point NPCAP_SDK_DIR at the extracted folder, e.g.\n"
            "  cmake -S . -B build -DNPCAP_SDK_DIR=C:/npcap-sdk")
    endif()

    add_library(pcap INTERFACE)
    target_include_directories(pcap INTERFACE "${PCAP_INCLUDE_DIR}")
    target_link_libraries(pcap INTERFACE "${PCAP_LIBRARY}")
    if(PACKET_LIBRARY)
        target_link_libraries(pcap INTERFACE "${PACKET_LIBRARY}")
    endif()
    target_link_libraries(pcap INTERFACE ws2_32)
    set(PCAP_TARGET pcap)
else()
    find_package(PkgConfig REQUIRED)
    # Optional prefix holding libpcap.pc, for systems that ship the runtime
    # library without its development headers (see README, "Compilation"):
    #   cmake -S . -B build -DPCAP_PREFIX=/opt/libpcap
    set(PCAP_PREFIX "" CACHE PATH
        "Prefix containing libpcap.pc (in lib/pkgconfig or lib64/pkgconfig)")
    if(PCAP_PREFIX)
        set(_pcap_pc_prefix
            "${PCAP_PREFIX}/lib64/pkgconfig:${PCAP_PREFIX}/lib/pkgconfig")
        if(DEFINED ENV{PKG_CONFIG_PATH} AND NOT "$ENV{PKG_CONFIG_PATH}" STREQUAL "")
            set(ENV{PKG_CONFIG_PATH} "${_pcap_pc_prefix}:$ENV{PKG_CONFIG_PATH}")
        else()
            set(ENV{PKG_CONFIG_PATH} "${_pcap_pc_prefix}")
        endif()
    endif()
    pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
    set(PCAP_TARGET PkgConfig::PCAP)
endif()

# ---------------------------------------------------------------------------
# Core library: no GUI dependency, unit-testable headless.
# ---------------------------------------------------------------------------
add_library(etherape_core STATIC
    src/decoder.cpp
    src/decoder.h
    src/netbios.cpp
    src/netbios.h
    src/zones.cpp
    src/zones.h
    src/ipreassembly.cpp
    src/ipreassembly.h
    src/helperpath.cpp
    src/helperpath.h
    src/displayfilter.cpp
    src/displayfilter.h
    src/graphmodel.cpp
    src/graphmodel.h
    src/xmlexport.cpp
    src/xmlexport.h
    src/jsonexport.cpp
    src/jsonexport.h
)
target_include_directories(etherape_core PUBLIC src)
target_link_libraries(etherape_core PUBLIC Qt6::Core Qt6::Gui Qt6::Network ${PCAP_TARGET})

if(WIN32)
    enable_language(RC)
    # The version block is generated so it always matches PROJECT_VERSION.
    configure_file(data/windows.rc.in
                   "${CMAKE_CURRENT_BINARY_DIR}/windows.rc" @ONLY)
    set(ET_WIN_RC "${CMAKE_CURRENT_BINARY_DIR}/windows.rc")
    # windres must find etherape.ico, which stays in the source tree.
    set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/windows.rc"
        PROPERTIES COMPILE_FLAGS "-I${CMAKE_CURRENT_SOURCE_DIR}/data")
else()
    set(ET_WIN_RC "")
endif()

add_executable(etherape2026
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/captureworker.cpp
    src/captureworker.h
    src/capturehelper.cpp
    src/capturehelper.h
    src/conversationsdialog.cpp
    src/conversationsdialog.h
    src/graphview.cpp
    src/graphview.h
    src/statspanel.cpp
    src/statspanel.h
    src/trafficchart.cpp
    src/trafficchart.h
    src/preferencesdialog.cpp
    src/preferencesdialog.h
    translations.qrc
    ${ET_WIN_RC}
)

qt_add_resources(etherape2026 "appresources"
    PREFIX "/"
    FILES data/etherape.png data/etherape.ico
)

target_link_libraries(etherape2026 PRIVATE
    etherape_core
    Qt6::Widgets
    Threads::Threads
)

if(WIN32)
    target_link_libraries(etherape2026 PRIVATE iphlpapi)
endif()

if(MSVC)
    target_compile_options(etherape2026 PRIVATE /W3 /utf-8)
    target_compile_options(etherape_core PRIVATE /W3 /utf-8)
else()
    target_compile_options(etherape2026 PRIVATE -Wall -Wextra)
    target_compile_options(etherape_core PRIVATE -Wall -Wextra)
endif()

target_compile_definitions(etherape2026 PRIVATE APP_VERSION="${PROJECT_VERSION}")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
    find_package(Qt6 REQUIRED COMPONENTS Test)
    add_executable(tst_core tests/tst_core.cpp)
    target_link_libraries(tst_core PRIVATE etherape_core Qt6::Test)
    add_test(NAME core COMMAND tst_core)
endif()

# Console subsystem on Windows keeps startup errors visible; set
# -DETH_WINDOWS_GUI=ON for a windowed build.
option(ETH_WINDOWS_GUI "Build a windowed (no console) executable on Windows" OFF)
if(WIN32 AND ETH_WINDOWS_GUI)
    set_target_properties(etherape2026 PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

install(TARGETS etherape2026 RUNTIME DESTINATION bin)
install(FILES data/etherape2026.desktop DESTINATION share/applications)
install(FILES data/etherape.png DESTINATION share/pixmaps RENAME etherape2026.png)
install(FILES etherape2026.1 DESTINATION share/man/man1)

# Windows deployment helper: windeployqt copies the Qt runtime next to the exe.
if(WIN32)
    find_program(WINDEPLOYQT_EXE windeployqt HINTS "${QT6_INSTALL_PREFIX}/bin")
    if(WINDEPLOYQT_EXE)
        add_custom_target(deploy
            COMMAND "${WINDEPLOYQT_EXE}" --no-translations --compiler-runtime
                    "$<TARGET_FILE:etherape2026>"
            DEPENDS etherape2026
            COMMENT "Deploying Qt runtime with windeployqt")
    endif()
endif()
