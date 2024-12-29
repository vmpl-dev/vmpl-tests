#!/bin/bash

# 版本号
MXML_VERSION="4.0.3"
# 文件名
FILE_NAME="mxml-${MXML_VERSION}.tar.gz"
# 安装路径
INSTALL_PREFIX=${1:-"/usr/local"}

# 下载源码
test -f ${FILE_NAME} || wget https://github.com/michaelrsweet/mxml/releases/download/v${MXML_VERSION}/${FILE_NAME}
tar xzf ${FILE_NAME}
cd mxml-${MXML_VERSION}

# 配置、编译和安装
./configure --prefix=${INSTALL_PREFIX}
make -j$(nproc)
sudo make install

echo "mxml has been installed to ${INSTALL_PREFIX}"
