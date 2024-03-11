# VMPL-Process Test Suite

## Build with libcheck

采用libcheck单元测试框架的自动化测试

```bash
./configure --enable-debug
make -j$(nproc) all
```

## Docker Test

### Build docker image

```bash
# 进入docker目录
cd ~/vmpl-process/docker
# 构建docker镜像
sudo docker build -t vmpl-process .
```

```bash
docker run -it -v$(pwd):/root/app --workdir=/root/app andrewd/musl-clang /bin/bash
```

### Build pcre2-10.43

```bash
tar -xvf pcre2-10.43.tar.gz
cd ~/pcre2-10.43
CC=musl-gcc ./configure --prefix=/usr/local/musl
make install -j128
```

### Build lighttpd-1.4.74

```bash
wget https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.74.tar.xz
tar -xvf lighttpd-1.4.74.tar.xz
cd lighttpd-1.4.74
CC=musl-gcc ./configure --prefix=/usr/local/musl
make install -j128
```

```bash
# ApacheBench Test
ulimit -n 10000
ab -n 10000 -c 1300 http://localhost:18888
```

## SPEC CPU 2017 Test

[SPEC-cpu2006的详细使用一键安装、手动安装。](https://blog.csdn.net/weixin_42480467/article/details/121903703)

[CPU计算性能speccpu2006的测试方法及工具下载](https://blog.csdn.net/wkl_venus/article/details/127688671)

[SPEC CPU简介和使用](https://blog.csdn.net/qq_36287943/article/details/103601539)

[SpecCPU2017 测试cpu性能](https://www.cnblogs.com/xiaoqi-home/p/15981359.html)

[speccpu2017的安装与运行](https://blog.csdn.net/weixin_45520085/article/details/131303231)

[Install / execute spec cpu2006 benchmark](https://sjp38.github.io/post/spec_cpu2006_install/)

### Run tests

```bash
sudo ./run-app.sh --load --loglevel debug --run ./benchmark
```

## Redis-6.2.5 Test

### Redis-6.2.5 on VM

### 启动redis server on VM (vmpl disabled)

```bash
# 启动redis
redis-server ~/redis.conf
# 连接redis
redis-cli
```

### 启动redis server on VM (vmpl enabled)

```bash
sudo ./run-app.sh --dunify ./dunify.so --run /usr/local/muslbin/redis-server ./redis.conf
```

### 测试redis server

```bash
# 测试redis server
redis-benchmark -h
```

## lmbench-2.5

## Memcached-1.6.9 Test

### 启动memcached server on VM

```bash
# 安装libmemcached-tools
sudo apt install libmemcached-tools
# 启动memcached 单线程 64MB内存 11211端口
memcached -u root -m 64 -p 11211 -t 1
memcached-tool
```

### 测试memcached server

```bash
# 测试memcached server
memcached-benchmark -h
```

### Rsync /usr/local/musl to VM

```bash
rsync -avzP /usr/local/musl/ amd-guest:/usr/local/musl/
```

### nginx benchmark

```bash
# 启动nginx
sudo ./run-app.sh --dunify ./dunify.so --run /usr/local/muslbin/nginx -c /usr/local/musl/etc/nginx/nginx.conf
# 测试nginx
ab -n 100000 -c 1000 http://localhost:8080/
```
