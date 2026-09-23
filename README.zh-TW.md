# Ko Bing

[English](README.md) | [简体中文](README.zh-CN.md) | **繁體中文**

[![Telegram](https://img.shields.io/static/v1?label=Telegram&message=@kobing_hide&color=0088cc)](https://t.me/kobing_hide)  [![CI Build](https://github.com/haitaogao58/kobing/actions/workflows/ci.yml/badge.svg)](https://github.com/haitaogao58/kobing/actions/workflows/ci.yml)

Android Keystore Spoofer 的自定義 keystore 實現（中文說明）

## 這是什麼？

這是一個完整的 keystore 實現，完整實現了 AOSP 的 AIDL 接口，參考官方 AOSP 實現編寫。

理論上，這會讓檢測器更難識別出與 AOSP 不一致的行為，從而比 TrickyStore 的 FOSS 分支，或基於 TrickyStore 的其它模組（如 TEESimulator）具備更強的隱蔽性。

## 環境要求

- **Android 12 或更高版本**。
- **arm64-v8a**（本倉庫發布產物僅針對 arm64-v8a）。
- 需要 KernelSU / Magisk 等支持模組的管理器。

## 安裝與配置

1. 刷入本模組。

2. 如有需要，[配置 KOBING](docs/CONFIGURATION.zh-TW.md)。

3. 替換模板 keybox.xml（如果需要）。

keybox 文件必須是**合法的** XML，且同時包含 EC 與 RSA 證書鏈；即其中不能含有水印、不可見字符等額外內容。

生效的配置/數據文件為：

- `/data/surprise/waste/config.toml`
- `/data/surprise/injector.toml`
- 包名允許清單 `/data/surprise/bm.txt`

完整的帶註釋示例、逐字段說明、安全須知與重啟要求，請閱讀[配置指南](docs/CONFIGURATION.zh-TW.md)。

## 重啟 keymint 與 injector

模組自帶兩個後台守護進程：一個用於 `keymint`，一個用於 `injector`。可用以下命令重啟：

```sh
touch /data/surprise/waste/restart.keymint
touch /data/surprise/waste/restart.injector
touch /data/surprise/waste/restart.all
```

哪些改動需要重啟組件、哪些需要整機重啟，見[配置指南](docs/CONFIGURATION.zh-TW.md#改動如何被加載)。

## 許可證

**使用本軟件前，您必須同時同意以下兩份許可證。**

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
1. 您不得將本軟件、本軟件的任意部分或將本軟件作為依賴的軟件用於任何商業用途。該
   商業用途包括但不限於以盈利為目的，將本軟件、本軟件的任意部分或將本軟件作為依
   賴的軟件與其他資源、物品或服務捆綁銷售。

2. 您不得暗示或明示本軟件與其他軟件有任何從屬關係。

3. 未經本軟件作者書面允許，您不得超出合理使用範圍或協議許可範圍使用本軟件的名稱。

4. 除非您所在的司法管轄區的適用法律另行規定，您同意將糾紛或爭議提交至中國大陸境
   內有管轄權的人民法院管轄。

5. 本協議與GNU Affero General Public License（以下簡稱AGPL）共同發揮效力，
   當本協議內容與AGPL衝突時，應當優先應用本協議內容，本協議僅覆蓋本軟件作者擁有
   完全著作權的部分，對於使用其他協議的軟件代碼不發揮效力。
```

## 致謝

部分代碼來自 [AOSP](https://source.android.com/)

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