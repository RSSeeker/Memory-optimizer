# 内存整理工具（Memory Optimizer）

Windows 一键内存整理的独立工具：释放被系统文件缓存与待机列表占用的内存。
纯 Rust 标准库 + Windows FFI，零第三方依赖。

## 功能

- 开启 `SeProfileSingleProcessPrivilege` / `SeIncreaseQuotaPrivilege` 特权；
- 通过 `NtSetSystemInformation` 清理系统文件缓存、修剪待机/已修改内存列表、触发内存合并；
- 非管理员运行时自动通过 UAC 重新以管理员身份执行；
- 报告整理前后可用内存与释放的内存大小。

## 编译

```bash
cd tools/memory-optimizer
cargo build --release
```

产物位于 `target/release/memory-optimizer.exe`。

## 用法

| 命令 | 说明 |
| --- | --- |
| `memory-optimizer.exe` | 一键整理内存（非管理员时自动弹出 UAC） |
| `memory-optimizer.exe --status` | 只读查看内存与管理员权限状态 |
| `memory-optimizer.exe --memory-optimize` | 提权辅助模式（内部使用） |

双击运行时会在结束后暂停等待回车；从终端运行时直接返回。

## 行为说明

- 仅支持 Windows。
- 退出码：0 表示成功，1 表示失败（含 UAC 被拒绝）。
