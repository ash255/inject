# inject
通用动态注入框架的其中一种实现

## support
支持系统windows、linux
支持处理器arm、x86_64、mips

## Note
linux中还可以使用LD_PRELOAD来实现注入
命令例子：
env $LD_PRELOAD="/home/test/test.so" ./test_inject
