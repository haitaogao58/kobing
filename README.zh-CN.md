# Ko Bing

[English](README.md) | **简体中文**

[![Telegram](https://img.shields.io/static/v1?label=Telegram&message=@kobing_hide&color=0088cc)](https://t.me/kobing_hide)  [![CI Build](https://github.com/haitaogao58/kobing/actions/workflows/ci.yml/badge.svg)](https://github.com/haitaogao58/kobing/actions/workflows/ci.yml)

Android Keystore Spoofer 的自定义 keystore 实现（中文说明）

## 这是什么？

这是一个完整的 keystore 实现，完整实现了 AOSP 的 AIDL 接口，参考官方 AOSP 实现编写。

理论上，这会让检测器更难识别出与 AOSP 不一致的行为，从而比 TrickyStore 的 FOSS 分支，或基于 TrickyStore 的其它模块（如 TEESimulator）具备更强的隐蔽性。

## 环境要求

- **Android 12 或更高版本**。
- **arm64-v8a**（本仓库发布产物仅针对 arm64-v8a）。
- 需要 KernelSU / Magisk 等支持模块的管理器。

## 安装与配置

1. 刷入本模块。

2. 如有需要，[配置 KOBING](docs/CONFIGURATION.md)。

3. 替换模板 keybox.xml（如果需要）。

keybox 文件必须是**合法的** XML，且同时包含 EC 与 RSA 证书链；即其中不能含有水印、不可见字符等额外内容。

生效的配置/数据文件为：

- `/data/surprise/waste/config.toml`
- `/data/surprise/injector.toml`
- 包名允许清单 `/data/surprise/bm.txt`

完整的带注释示例、逐字段说明、安全须知与重启要求，请阅读[配置指南](docs/CONFIGURATION.md)。

## 重启 keymint 与 injector

模块自带两个后台守护进程：一个用于 `keymint`，一个用于 `injector`。可用以下命令重启：

```sh
touch /data/surprise/waste/restart.keymint
touch /data/surprise/waste/restart.injector
touch /data/surprise/waste/restart.all
```

哪些改动需要重启组件、哪些需要整机重启，见[配置指南](docs/CONFIGURATION.md#how-changes-are-loaded)。

## 许可证

**使用本软件前，您必须同时同意以下两份许可证。**

`AGPL-3.0-or-later`

```plaintext
KoBing - Custom keymint implementation for Android Keystore Spoofer
Copyright (C) 2025 KoBing <kobing@kobing.top>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

`Ko Bing License`

```plaintext
1. 您不得将本软件、本软件的任意部分或将本软件作为依赖的软件用于任何商业用途。该
   商业用途包括但不限于以盈利为目的，将本软件、本软件的任意部分或将本软件作为依
   赖的软件与其他资源、物品或服务捆绑销售。

2. 您不得暗示或明示本软件与其他软件有任何从属关系。

3. 未经本软件作者书面允许，您不得超出合理使用范围或协议许可范围使用本软件的名称。

4. 除非您所在的司法管辖区的适用法律另行规定，您同意将纠纷或争议提交至中国大陆境
   内有管辖权的人民法院管辖。

5. 本协议与GNU Affero General Public License（以下简称AGPL）共同发挥效力，
   当本协议内容与AGPL冲突时，应当优先应用本协议内容，本协议仅覆盖本软件作者拥有
   完全著作权的部分，对于使用其他协议的软件代码不发挥效力。
```

## 致谢

部分代码来自 [AOSP](https://source.android.com/)

License: `Apache-2.0`

```plaintext
Copyright 2022, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
