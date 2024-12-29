cmake_minimum_required(VERSION 3.10)
project(vmpl-tests 
    LANGUAGES C
    VERSION 1.0.0
)

# 设置安装前缀
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()

# 包含 GNUInstallDirs 以获取标准安装目录定义
include(GNUInstallDirs)

# 设置通用编译选项
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(
    -Wall -g -O2
    -mxsave          # 支持 XSAVE 指令
    -mxsaveopt       # 支持 XSAVEOPT 指令
    -mavx            # 支持 AVX 指令
    -msse            # 支持 SSE 指令
    -msse2           # 支持 SSE2 指令
    -DXSAVE         # 定义 XSAVE 宏
)

# 设置动态链接为默认
set(BUILD_SHARED_LIBS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 设置库的查找路径
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")
link_directories(/usr/local/lib)

# 创建可执行文件
add_executable(benchmark
    src/benchmark.c
    src/server.c
    src/client.c
    src/test_sys.c
    src/test_proc.c
    src/test_signal.c
    src/test_sem.c
    src/test_ipc.c
    src/test_mem.c
    src/test_vdso.c
    src/test_security.c
    src/test_misc.c
    src/test_zlib.c
    src/test_mxml.c
)

# 添加包含目录
target_include_directories(benchmark PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# 查找依赖库
find_library(DUNE_LIB dune REQUIRED)
find_library(VMPL_LIB vmpl REQUIRED)
find_library(HOTCALLS_LIB hotcalls REQUIRED)
find_library(DICT_LIB dict REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB)
find_package(Check)

# 链接库
target_link_libraries(benchmark PRIVATE
    ${DUNE_LIB}
    ${VMPL_LIB}
    ${HOTCALLS_LIB}
    ${DICT_LIB}
    Threads::Threads
)

# 条件编译和链接
if(ZLIB_FOUND)
    target_sources(benchmark PRIVATE src/test_zlib.c)
    target_link_libraries(benchmark PRIVATE ZLIB::ZLIB)
    target_compile_definitions(benchmark PRIVATE HAVE_ZLIB=1)
endif()

if(Check_FOUND)
    target_link_libraries(benchmark PRIVATE Check::Check)
    target_compile_definitions(benchmark PRIVATE HAVE_CHECK=1)
endif()

# 安装配置
install(TARGETS benchmark
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT runtime
)

# CPack配置
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_NAME "vmpl-tests")
set(CPACK_PACKAGE_VENDOR "VMPL")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "VMPL Tests Package")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})

# DEB包配置
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "VMPL Team <vmpl@example.com>")
set(CPACK_PACKAGE_CONTACT "VMPL Team <vmpl@example.com>")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libvmpl (>= 1.0.0), libdune (>= 1.0.0), libhotcalls (>= 1.0.0), libdict (>= 1.0.0)")
set(CPACK_DEBIAN_PACKAGE_SECTION "devel")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

# 必须在设置完所有CPACK变量后包含CPack
include(CPack)