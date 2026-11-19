cmake_minimum_required(VERSION 3.21)
project(etherape2026 VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets Network)

# Build-only dependency prefix: when the system ships libpcap without its
# development headers, a private prefix extracted from the distribution RPMs
# keeps the build reproducible (see README, "Compilation").
if(NOT DEFINED ENV{PKG_CONFIG_PATH}
   AND EXISTS "$ENV{HOME}/.local/etherape-deps/usr/lib64/pkgconfig/libpcap.pc")
    set(ENV{PKG_CONFIG_PATH}
        "$ENV{HOME}/.local/etherape-deps/usr/lib64/pkgconfig")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
find_package(Threads REQUIRED)

qt_standard_project_setup()

add_executable(etherape2026
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/captureworker.cpp
    src/captureworker.h
    src/capturehelper.cpp
    src/capturehelper.h
    src/decoder.cpp
    src/decoder.h
    src/graphmodel.cpp
    src/graphmodel.h
    src/graphview.cpp
    src/graphview.h
    src/statspanel.cpp
    src/statspanel.h
    src/preferencesdialog.cpp
    src/preferencesdialog.h
)

target_link_libraries(etherape2026 PRIVATE
    Qt6::Widgets
    Qt6::Network
    PkgConfig::PCAP
    Threads::Threads
)

target_compile_options(etherape2026 PRIVATE -Wall -Wextra)
target_compile_definitions(etherape2026 PRIVATE APP_VERSION="${PROJECT_VERSION}")

install(TARGETS etherape2026 RUNTIME DESTINATION bin)
install(FILES data/etherape2026.desktop DESTINATION share/applications)
install(FILES data/etherape.png DESTINATION share/pixmaps RENAME etherape2026.png)
