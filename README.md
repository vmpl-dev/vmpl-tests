# VMPL-Process Test Suite
## Build with out libcheck
不采用libcheck单元测试框架的手动测试
~~~bash
./configure
make -j$(nproc) all
~~~

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
sudo ./benchmark -ttest_process
~~~