#!/bin/bash

# 普通构建
rm -rf build
mkdir -p build && cd build
rm -rf CMakeCache.txt CMakeFiles
cmake ..
make

# 生成 DEB 包
cpack -G DEB
dpkg -c vmpl-tests_1.0.0_amd64.deb