#!/bin/bash

# 设置版本和安装路径
CHECK_VERSION="0.15.2"
INSTALL_PREFIX=${1:-"/usr/local"}

# 创建临时目录
BUILD_DIR=$(mktemp -d)
cd $BUILD_DIR

# 下载源码
wget https://github.com/libcheck/check/releases/download/${CHECK_VERSION}/check-${CHECK_VERSION}.tar.gz
tar xzf check-${CHECK_VERSION}.tar.gz
cd check-${CHECK_VERSION}

# 配置、编译和安装
mkdir build && cd build
cmake .. \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DCMAKE_BUILD_TYPE=Release

make -j$(nproc)
sudo make install

# 清理
cd /
rm -rf $BUILD_DIR

echo "libcheck has been installed to ${INSTALL_PREFIX}" 