# SecNeo 通用脱壳工具

`secneo_unpack.py` —— 面向 **SecNeo（梆梆安全，DexHelper）** 加固 APK 的
用户态脱壳器。不需要真机、root 或 Frida，全部在 AndroCorn 的 ARM64
模拟器里完成。

```bash
python tools/secneo_unpack.py test.apk -o unpacked
```

输出：

```
unpacked/
├── app-dex.zip              # multidex，jadx / baksmali 可直接打开
├── report.json              # 每个 dex 的偏移、大小、类数、方法数、sha256
├── inner_libDexHelper.so    # 壳解密出的内层 DexHelper 镜像
└── _work/libDexHelper.so    # 从 APK 里取出的外层壳
```

## 它做了什么

| 阶段 | 说明 |
|---|---|
| 1. 取壳 | 从 APK 的 `lib/<abi>/libDexHelper.so` 取出加载器，`classes.dex` 取出壳 dex |
| 2. 读壳类 | 解析 `com.secneo.apkwrapper.H` 的字段声明，并从 `<clinit>` 的 DEX 字节码里恢复初值（这类壳的 `static_values` 是空的） |
| 3. 载入 | AndroCorn 的 linker 加载外层壳，跑完它的 `init_array`；壳自己用 RC4 解出内层 DexHelper 并 mmap |
| 4. 定位 | 在内存里找内层 ELF，解析 `JNI_OnLoad`（符号表不可信时用行为特征，见下） |
| 5. 调用 | 以 `JavaVM*` 调 `JNI_OnLoad`，壳注册全部 native 方法并进入 dex 安装流程 |
| 6. 绕过 ART | 壳假定 `art::Runtime::instance_` 一定存在；查不到就空指针崩溃。工具会自动定位那次符号查询函数并安装"假符号"垫片后重试 |
| 7. 收集 | 扫描全内存，按 SHA-1 + Adler-32 + header 校验挑出所有合法 dex，按 sha256 去重 |

## 三个关键点

**fork 语义。** 壳的反调试会 `fork()` 出子进程做自检，子进程里
`getpid()` 必须返回自己的 pid。AndroCorn 原来一律返回主进程 pid，
壳据此判定"被调试"并 `kill(getpid(), SIGKILL)`。补丁修好后自检才能过。

**JNI 返回 NULL。** Java 侧字段为 null 时，AndroCorn 的 JNI 桩不写 X0，
寄存器里留下上一次的垃圾值，壳会把它当 jobject 用。补丁改为显式写 0。

**JNI_OnLoad 的符号被篡改。** 内层 .so 的动态符号表里
`JNI_OnLoad` 的 `st_value` 是 `0x3FE498B4`，真实偏移是 `0x148B4`——
SecNeo 故意写坏它。因此工具先看符号表是否落在镜像范围内，不可信时改用
行为特征：`JNI_OnLoad(JavaVM*, void*)` 必须先取 `JNIEnv`，典型指令是
`mov w2, #4`（JNI_VERSION_1_4）/ `#6` 加 `movk w2, #1, lsl #16`；
这对立即数在整个镜像里只出现一次，命中后向上回溯到函数起点即可。

## 依赖的 AndroCorn 补丁

以下改动是必须的（`secneo` 分支已经包含）：

| 文件 | 改动 | 原因 |
|---|---|---|
| `kernel/backend/filesystem/_io.py`<br>`kernel/callbacks/arm64.py` | 新增 `pread64` / `pwrite64`（syscall 0x43/0x44） | 壳第一个动作就是 `pread64`，原版直接抛 Unhandled syscall |
| `cpu/scheduler.py` | `Task` 增加 `proc_pid` / `ppid`；fork、线程、主任务分别赋值 | 见上「fork 语义」 |
| `kernel/backend/sysproc/process.py` | `_getpid` / `_getppid` 按当前 task 取 | 同上 |
| `kernel/fs/nodes/proc.py` | `/proc/<pid>` 对任意 pid 都可解析 | 子进程会访问自己的 pid |
| `java/jni/main.py` | 字段/静态字段返回 `None` 时返回 0 | 见上「JNI 返回 NULL」 |
| `java/jni/main.py` | 实现 `get_long_array_elements` / `release_long_array_elements` | 壳通过 `DexFile.mCookie`（`long[]`）拿 dex 指针 |
| `java/classes/java/lang/clazz.py` | 新增 `DexCache` 与 `Class.dexCache` | 壳反射改 ART |
| `java/classes/java/lang/array.py` | 新增 `LongArray` | 同上 |
| `java/classes/java/io/file.py` | 新增 `path` 字段 | 壳读 `DexPathList$Element.path` |
| `java/classloader.py` | `JavaClassLoader.pathList` | 壳遍历 ClassLoader 找已加载的 dex |
| `java/classes/dalvik/system/dex_utils.py` | `DexPathList`、`DexPathListElement`、`InMemoryDexClassLoader`、`DexFile.mCookie` | 同上 |
| `kernel/backend/sysproc/signals.py` | `ANDROCORN_IGNORE_SELFKILL=1` 时忽略自杀 | 分析需要在壳反调试自毁后继续 |

跨版本的 SecNeo 可能换类名，用 `--wrapper-class` 指定，例如
`--wrapper-class Lcom/secneo/apkwrapper/H;`。

## 限制

* 只处理 **DexHelper 家族**（`com.secneo.apkwrapper.*`）。其他加固
  （爱加密、360、腾讯乐固）结构不同，不适用。
* 依赖壳自己完成解密：工具不实现任何密码学，只是把壳跑起来。
  如果壳在更早的环节就检测失败（比如发现没有 libart），工具会尝试
  自动垫片；超过 `--max-attempts` 次仍失败时会明确报错。
* 输出是"解密后的 dex"，不是原始 APK 的还原；ODEX/VDEX 等进一步
  优化产物不在范围内。

## 分支说明

本仓库的 `secneo` 分支包含运行该工具所需的全部补丁（见上表），
以及 `tools/secneo_unpack.py` 本身。上游 `main` 分支没有这些改动。
