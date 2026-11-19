cmake_minimum_required(VERSION 3.21)
project(etherape2026 VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets Network)
find_package(Threads REQUIRED)

qt_standard_project_setup()

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
    # Build-only dependency prefix: when the system ships libpcap without its
    # development headers, a private prefix extracted from the distribution
    # RPMs keeps the build reproducible (see README, "Compilation").
    if(NOT DEFINED ENV{PKG_CONFIG_PATH}
       AND EXISTS "$ENV{HOME}/.local/etherape-deps/usr/lib64/pkgconfig/libpcap.pc")
        set(ENV{PKG_CONFIG_PATH}
            "$ENV{HOME}/.local/etherape-deps/usr/lib64/pkgconfig")
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
    src/graphmodel.cpp
    src/graphmodel.h
    src/xmlexport.cpp
    src/xmlexport.h
    src/jsonexport.cpp
    src/jsonexport.h
)
target_include_directories(etherape_core PUBLIC src)
target_link_libraries(etherape_core PUBLIC Qt6::Core Qt6::Gui Qt6::Network ${PCAP_TARGET})

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
    src/preferencesdialog.cpp
    src/preferencesdialog.h
)

target_link_libraries(etherape2026 PRIVATE
    etherape_core
    Qt6::Widgets
    Threads::Threads
)

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
