cmake_minimum_required(VERSION 3.20)
project(PasswordManager VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# 优先查找静态库
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.lib")

# 查找依赖项
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(SQLite3 REQUIRED)

find_package(Qt6 COMPONENTS 
    Core 
    Widgets 
    Gui 
    Sql 
    Concurrent 
    REQUIRED
)

# 源文件列表
set(SOURCES
    main.cpp
    src/UserAuth.cpp
    src/PassWordGen.cpp
    src/CryptoModule.cpp
    src/PassWordVault.cpp
    ui/LoginWindow.cpp
    ui/MainWindow.cpp
    ui/PasswordManagerWindow.cpp
)

# 生成可执行文件
if(MINGW OR MSYS)  
    add_executable(PasswordManager WIN32 ${SOURCES})
else()
    add_executable(PasswordManager ${SOURCES})
endif()

# 包含目录
target_include_directories(PasswordManager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/ui
    ${SODIUM_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
)

# 链接库
target_link_libraries(PasswordManager PRIVATE
    PkgConfig::SODIUM
    SQLite::SQLite3
    Qt6::Core
    Qt6::Widgets
    Qt6::Gui
    Qt6::Sql
    Qt6::Concurrent
)

# 编译器定义
target_compile_definitions(PasswordManager PRIVATE
    QT_NO_KEYWORDS
    QT_SQL_LIB
    QT_CONCURRENT_LIB
)

# **Windows 平台特定配置**
if(WIN32)
    if(MINGW)  # MinGW
        target_link_options(PasswordManager PRIVATE 
            -Wl,-subsystem,windows
            -static
            -static-libgcc
            -static-libstdc++
        )
    else()  # MSVC
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS /MT")
    endif()
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)

    # **自动部署 Qt 依赖**
    add_custom_command(TARGET PasswordManager POST_BUILD
        COMMAND "C:\\msys64\\mingw64\\bin\\windeployqt6.exe" --release $<TARGET_FILE:PasswordManager>
        COMMENT "Deploying Qt runtime libraries..."
    )

endif()
