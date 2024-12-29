#!/bin/bash

# 设置版本和安装路径
ZLIB_VERSION="1.3.1"
INSTALL_PREFIX=${1:-"/usr/local"}

# 创建临时目录
BUILD_DIR=$(mktemp -d)
cd $BUILD_DIR

# 下载源码
wget https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz
tar xzf zlib-${ZLIB_VERSION}.tar.gz
cd zlib-${ZLIB_VERSION}

# 配置、编译和安装
./configure --prefix=${INSTALL_PREFIX}
make -j$(nproc)
sudo make install

# 清理
cd /
rm -rf $BUILD_DIR

echo "zlib has been installed to ${INSTALL_PREFIX}"
