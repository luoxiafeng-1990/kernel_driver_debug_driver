# Kernel Debug Tracer Module

内核驱动远程调试和跟踪系统的内核模块实现。

## 编译环境

### Docker 环境编译（推荐）

1. 在项目根目录执行：
   ```bash
   ./tools/workshop.sh
   ```

2. 选择选项：`2,1,0,0` 进入 Docker 编译环境

3. 在 Docker 环境中编译：
   ```bash
   cd debug
   # 首次编译需要先准备内核（如果需要）
   ./build.sh prepare
   # 然后编译模块
   ./build.sh build
   ```

   或者使用 Makefile：
   ```bash
   # 准备内核（如果需要）
   make prepare
   # 编译模块
   make riscv
   ```

### 本地环境编译

如果你有本地的内核开发环境：

```bash
cd debug
make all
```

## 编译脚本使用

`build.sh` 脚本会自动检测环境并选择合适的编译方式：

```bash
# 编译模块
./build.sh build

# 清理编译产物
./build.sh clean

# 准备内核（如果需要）
./build.sh prepare

# 显示编译配置
./build.sh config

# 显示帮助
./build.sh help
```

## Makefile 目标

- `make all` - 编译内核模块
- `make riscv` - RISC-V64 交叉编译
- `make clean` - 清理编译文件
- `make debug` - 带调试符号编译
- `make info` - 显示编译配置
- `make help` - 显示帮助信息

## 文件结构

```
debug/
├── Makefile                    # 编译配置
├── build.sh                   # 编译脚本
├── kernel_debug_tracer.h       # 核心头文件
├── main.c                      # 模块主入口
├── breakpoint_manager.c        # 断点管理
├── symbol_resolver.c           # 符号解析
├── kprobe_handler.c           # kprobe 处理
├── call_stack_tracer.c        # 调用栈跟踪
├── variable_extractor.c       # 变量提取
├── data_collector.c           # 数据收集
└── debugfs_interface.c        # 用户空间接口
```

## 编译输出

成功编译后会生成：
- `kernel_debug_tracer.ko` - 内核模块文件
- `*.mod.*` - 模块相关文件
- `*.o` - 目标文件

## 环境要求

### Docker 环境
- RISC-V64 交叉编译工具链
- 内核源码在 `../linux` 目录

### 本地环境
- 内核头文件包 (`linux-headers-*`)
- GCC 编译器
- Make 工具

## 故障排除

1. **找不到内核头文件**
   - 确保在正确的环境中编译
   - 检查 `KDIR` 路径是否正确

2. **交叉编译失败**
   - 确保在 Docker 环境中
   - 检查 `riscv64-unknown-linux-gnu-gcc` 是否可用

3. **内核配置错误**
   - 如果出现 "include/config/auto.conf are missing" 错误
   - 运行 `./build.sh prepare` 或 `make prepare` 来准备内核
   - 确保内核源码目录完整

4. **符号未定义错误**
   - 检查内核配置是否启用了相关功能
   - 确保内核版本兼容

## 使用方法

编译成功后，可以加载模块：

```bash
# 加载模块
insmod kernel_debug_tracer.ko

# 查看模块信息
lsmod | grep kernel_debug_tracer

# 卸载模块
rmmod kernel_debug_tracer
```

调试接口位于：`/sys/kernel/debug/kernel_debug_tracer/`