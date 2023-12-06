# VMPL-Process Test Suite

## Build with libcheck

采用libcheck单元测试框架的自动化测试

```bash
./configure --enable-debug
make -j$(nproc) all
```

## Docker Test
### Build docker image
~~~bash
# 进入docker目录
cd ~/vmpl-process/docker
# 构建docker镜像
sudo docker build -t vmpl-process .
~~~

```
docker run -it -v$(pwd):/root/app --workdir=/root/app andrewd/musl-clang /bin/bash
```

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
$ sudo ./run-app.sh --dunify ./dunify.so --run /usr/local/muslbin/redis-server ./redis.conf
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