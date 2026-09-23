# Changelog

## v1.2.4

WebUI 应用选择器与模块修复：

- **WebUI 应用选择器**：修复点击「选择应用」时卡死 WebUI 的问题——打开应用页不再一次性同步执行多条重命令；应用名称表改为优先读取开机预生成的 `apps_data.js`（`window.KB_APPS`），仅在缺失或为空时回退实时扫描。同时修复应用名称解析（Defect K）与应用列表只显示配置文件内条目的回归。
- **开机生成时机**：生成应用名称表前轮询等待 `pm` 就绪（最多约 180 秒），避免开机早期产出残缺表。
- **模块**：迁移遗留持久化文件至 `/data/surprise` 后再清理；`/data/surprise` 以 `0700` + keystore 属主创建（安装时与每次开机强制）；允许 keystore 监听 `system_data_root_file`（inotify）。
- **注入器**：`is_injected` 改为依据已记录的成功标记判定。
- **vbmeta**：Auto 信任解析失败时明确报错，不再随机回退。
- **CI**：构建触发分支修正为 `main`。
- 清理仓库内 `rustc-ice-*.txt` 编译崩溃转储。

## v1.2.3

模块机制重构与文档完善：

- **持久化数据布局统一迁移至 `/data/surprise`**：不再使用 `/data/adb/ko_bing` 与 `/data/misc/keystore/ko_bing` 的分散布局。实体目录三层结构为：`/data/surprise`（首页，`keybox.xml`、`injector.toml`、`bm.txt`）、`/data/surprise/waste`（`data`、`logs`、`config.toml`、`crash_count`、`rpc.sock`、`injector.payload`、pid 与 restart 文件）。包名允许清单直接落于 `/data/surprise/bm.txt`，不再使用软链。
- **`/data/surprise` 目录权限收紧为 `0700` 且属主为 keystore（1017:1017）**：安装时创建并设置，`post-fs-data.sh` 每次开机强制该权限。保留执行位，否则模块自身（uid 1017）无法穿越该目录访问 `keybox.xml` / `rpc.sock`；除 keystore 与 root 外其他 App 均无法进入。
- **PID 文件改短名**：`keymint-daemon.pid` → `keymint.pid`、`injector-daemon.pid` → `injector.pid`。
- **模块元数据**：`author` 改为 `haitaogao58`。
- **新增中文文档**：`README.zh-CN.md`。
- **移除 OTA 更新检查**：不再提供 `updateJson` / `update.json`。
- 修复 injector 配置测试隔离缺陷（`load_from_path_with_bm`），真机 `189 passed / 0 failed`。

## v1.2.2-webui

- 引入 WebUI（纯文字应用列表风格），支持可视化编辑包名允许清单。
- 软链与配置文档整理。
