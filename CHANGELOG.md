# Changelog

## v1.2.3

模块机制重构与文档完善：

- **持久化数据布局统一迁移至 `/data/surprise`**：不再使用 `/data/adb/ko_bing` 与 `/data/misc/keystore/ko_bing` 的分散布局。实体目录三层结构为：`/data/surprise`（首页，`keybox.xml`、`injector.toml`、`bm.txt`）、`/data/surprise/waste`（`data`、`logs`、`config.toml`、`crash_count`、`rpc.sock`、`injector.payload`、pid 与 restart 文件）。包名允许清单直接落于 `/data/surprise/bm.txt`，不再使用软链。
- **`/data/surprise` 目录权限收紧为 `0600`**：安装时创建并设置，`post-fs-data.sh` 每次开机强制该权限。
- **PID 文件改短名**：`keymint-daemon.pid` → `keymint.pid`、`injector-daemon.pid` → `injector.pid`。
- **模块元数据**：`author` 改为 `haitaogao58`。
- **新增中文文档**：`README.zh-CN.md`。
- **移除 OTA 更新检查**：不再提供 `updateJson` / `update.json`。
- 修复 injector 配置测试隔离缺陷（`load_from_path_with_bm`），真机 `189 passed / 0 failed`。

## v1.2.2-webui

- 引入 WebUI（纯文字应用列表风格），支持可视化编辑包名允许清单。
- 软链与配置文档整理。
