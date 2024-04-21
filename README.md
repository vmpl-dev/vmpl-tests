# VMPL-Process Test Suite

## Build with libcheck

采用libcheck单元测试框架的自动化测试

```bash
./configure --enable-debug
make -j$(nproc) all
```


### Run tests

```bash
sudo ./run-app.sh --load --loglevel debug --run ./benchmark
```
