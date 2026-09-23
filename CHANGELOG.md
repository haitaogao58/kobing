# Changelog

## v1.2.3

模块机制重构与文档完善：

- **包名允许清单软链重命名**：`/data/adb/ko_bing/bm.txt` → `/data/adb/ko_bing/kobing_bm.txt`（`kobing_` 前缀），涉及 `post-fs-data.sh`、`customize.sh`、WebUI 与文档。实体文件仍为 `/data/surprise/kobing_bm.txt`。
- **PID 文件改短名**：`keymint-daemon.pid` → `keymint.pid`、`injector-daemon.pid` → `injector.pid`。
- **模块元数据**：`author` 改为 `haitaogao58`；`updateJson` 指向本仓库自托管更新清单。
- **新增中文文档**：`README.zh-CN.md`。
- **新增自托管 OTA**：仓库根目录 `update.json`（main 分支），支持 KernelSU / Magisk 管理器检查更新。
- 修复 injector 配置测试隔离缺陷（`load_from_path_with_bm`），真机 `189 passed / 0 failed`。

## v1.2.2-webui

- 引入 WebUI（纯文字应用列表风格），支持可视化编辑包名允许清单。
- 软链与配置文档整理。
