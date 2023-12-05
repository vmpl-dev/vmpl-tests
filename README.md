# VMPL-Process Test Suite
## Build with libcheck
采用libcheck单元测试框架的自动化测试
~~~bash
./configure --enable-debug
make -j$(nproc) all
~~~

### Run tests
~~~bash
# 加载内核模块（vmpl-process）
./load.sh --load
# 输出有哪些测试
./benchmark -l
# 执行test_process测试程序
sudo ./run-app.sh --load --loglevel debug --run ./benchmark
~~~

[x] System Calls
- [x] process
- [x] sys
- [x] prctl
- [x] rdtsc
- [x] syscall
- [x] vsyscall
[x] Process Management
- [x] fork
- [x] vfork
- [x] pthread
- [x] posted_ipi
- [x] self-posted ipi
[x] Virtual Memory
- [x] mmap
- [x] mprotect
- [x] munmap
- [x] brk
[x] Inter-Process Communication
- [x] pipe
- [x] socket
- [x] signal
- [x] shm
- [x] sem
- [x] msg
[x] vDSO
- [x] gettimeofday
- [x] time
- [x] clock_gettime
- [x] getcpu
- [x] getrandom
- [x] getentropy
[x] Security
- [x] seccomp
[x] Misc
- [x] xml
- [x] zlib
- [x] json

## Redis-6.2.5 Test
### Redis-6.2.5 on Host
```bash
# 进入redis-6.2.5目录
cd ~/rpmbuild/BUILD/redis-6.2.5
# 查看是否添加了VMPL_ENTER宏
grep VMPL_ENTER -rn -A2 -B2 src/
# 查看是否main函数后添加了VMPL_ENTER宏
grep 'main(' -rn -A2 -B2 src/
# 编译 redis-6.2.5
make CC=musl-gcc LDFLAGS=-lvmpl MALLOC=tcalloc all -j$(nproc)
# 安装 redis-6.2.5
sudo make install PREFIX=/usr/local/musl/
# 将redis.conf文件拷贝到虚拟机中
scp redis.conf amd-guest:~/redis.conf
```

### Redis-6.2.5 on VM
```bash
# 同步/usr/local/musl文件夹到虚拟机中
sudo rsync -avzP benshan@super-server:/usr/local/musl/ /usr/local/musl/
```

### 启动redis server on VM (vmpl disabled)
```bash
# 启动redis
redis-server ~/redis.conf
# 连接redis
redis-cli
```

### 启动redis server on VM (vmpl enabled)
```bash
$ sudo ./run-app.sh --dunify ./dunify.so --run /usr/local/musl/bin/redis-server ./redis.conf
```

### 测试redis server
```bash
# 测试redis server
redis-benchmark -h
```

## lmbench-2.5
### 安装 libtirpc
```bash
# 编译libtirpc
cd ~/home
# 下载libtirpc
git clone git://linux-nfs.org/~steved/libtirpc
# 进入libtirpc目录
cd libtirpc
# 配置libtirpc
./configure --prefix=/usr/local/musl --disable-gssapi
# 编译libtirpc
make all CC=musl-gcc -j$(nproc)
```

### 安装 lmbench-2.5
```bash
# 编译lmbench
# https://www.francisz.cn/2022/05/12/lmbench/
# 下载lmbench
wget https://master.dl.sourceforge.net/project/lmbench/lmbench/2.5/lmbench-2.5.tgz
# 解压lmbench
tar -zxvf lmbench-2.5.tgz
# 进入lmbench目录
cd ~/home/lmbench
# 编译lmbench
make CC=musl-gcc -j$(nproc)
```

## Memcached-1.6.9 Test
### 安装 linux内核头文件
```bash
# 进入linux-svsm目录
cd ~/linux-svsm/scripts/linux/guest
# 安装 linux内核头文件
sudo make headers_install INSTALL_HDR_PATH=/usr/local/musl/
```
### 安装 openssl-1.1.1k
```bash
# 进入openssl-1.1.1k目录
cd ~/rpmbuild/BUILD/openssl-1.1.1k
# 配置 openssl-1.1.1k
./config --prefix=/usr/local/musl
# 编译 openssl-1.1.1k
make CC=musl-gcc LDFLAGS=-lvmpl all -j$(nproc)
# 安装 openssl-1.1.1k
sudo make install PREFIX=/usr/local/musl/
```

### 安装 libevent-2.1.12-stable
```bash
# 进入libevent-2.1.12-stable目录
cd ~/rpmbuild/BUILD/libevent-2.1.12-stable
# 配置 libevent-2.1.12-stable
./configure --prefix=/usr/local/musl
# 编译 libevent-2.1.12-stable
make CC=musl-gcc CFLAGS=--sysroot=/usr/local/musl LDFLAGS=-lvmpl all -j$(nproc)
# 安装 libevent-2.1.12-stable
sudo make install PREFIX=/usr/local/musl/
```

### Memcached-1.6.9 on Host
```bash
# 进入memcached-1.6.9目录
cd ~/rpmbuild/BUILD/memcached-1.6.9
# 查看是否添加了VMPL_ENTER宏
grep VMPL_ENTER -rn -A2 -B2 src/
# 查看是否main函数后添加了VMPL_ENTER宏
grep 'main(' -rn -A2 -B2 src/
# 配置 memcached-1.6.9，设置--disable-coverage
./configure --prefix=/usr/local/musl --disable-coverage
# 编译 memcached-1.6.9
make CC=musl-gcc CFLAGS=-Wno-array-bounds LDFLAGS=-lvmpl all -j$(nproc)
# 安装 memcached-1.6.9
sudo make install PREFIX=/usr/local/musl/
```

### Memcached-1.6.9 on VM
```bash
# 同步/usr/local/musl文件夹到虚拟机中
sudo rsync -avzP benshan@super-server:/usr/local/musl/ /usr/local/musl/
```

### 启动memcached server on VM
```bash
# 启动memcached
memcached -u root -m 64 -p 11211 -d
# 连接memcached
memcached-tool
```

### 测试memcached server
```bash
# 测试memcached server
memcached-benchmark -h
```