# 配置指南

[English](CONFIGURATION.md) | **简体中文** | [繁體中文](CONFIGURATION.zh-TW.md)

KoBing（KOBING）使用三个生效的配置文件：

- `/data/surprise/waste/config.toml` 控制 KeyMint 服务、其上报的身份，以及用于 KOBING 创建的密钥的机密。
- `/data/surprise/injector.toml` 选择哪些 KeyStore 请求被路由到 KOBING。
- `/data/surprise/bm.txt` 列出可以使用 KOBING 的应用包。

本指南描述当前构建所使用的生效配置。示例之后附有独立的逐字段参考，因此示例中的简短注释并非唯一的说明。

**跳转：** [`config.toml`](#configtoml) | [`injector.toml`](#injectortoml) | [`bm.txt`](#bmtxt)

## 编辑之前

对于一般使用，通常唯一需要修改的设置是 `bm.txt` 中的包名允许清单。请保持 `injector.toml`、安全过滤器、所有 `[intercept]` 开关以及生成的 `[crypto]` 值不变。

在进行修改之前：

1. 对所有生效文件做一份私有备份。
2. 编辑 `/data/surprise/`（以及 `/data/surprise/waste/`）下的文件，而不是模块 ZIP 中的副本。
3. 保持字符串在引号内，布尔值使用 `true` 或 `false`，并将包名放入 `bm.txt`，每行一个精确的包名。
4. 每次只改动一处，保存完整文件，并在改动后检查对应的日志。

切勿公开 `[crypto]` 值、IMEI、IMEI2、MEID、序列号，或任一配置文件的未脱敏副本。

## 改动如何被加载

两个组件都会监视其生效文件以获得有效改动。它们的行为并不完全相同：

- 有效的 `injector.toml` 或 `bm.txt` 会应用到新请求，无需重启。
- 有效的 `config.toml` 会被自动读取，但只有四个补丁级别字段和生物识别兼容开关能够在不重启 keymint 的情况下完全生效。下方的字段参考会说明何时需要重启。
- 在组件运行期间保存的格式错误的文件会被拒绝，内存中最后一个有效配置保持生效。
- 若 keymint 启动时存在格式错误的 `config.toml`，会阻止 keymint 启动。修正该文件并重启 keymint。
- 若 injector 启动时存在格式错误的 `injector.toml`，KOBING 请求路由将保持禁用。保存一个有效文件可让监视器自动恢复路由；仅当无法恢复时才重启 injector。
- 若组件启动时任一文件缺失，KOBING 会创建一个带有生成默认值的新文件。这并不是重置可用配置的安全方式：重新生成的机密无法恢复由先前机密保护的密钥。

重启命令记录在[重启 keymint 与 injector](../README.zh-CN.md#重启-keymint-与-injector)中。在更改应用路由后，请关闭并重新打开受影响的应用，以避免将已打开的操作与新路由混用。若需要进程重启来获得清晰的边界，只需重启 injector。仅针对 injector 的设置更改不需要重启 keymint。

## `config.toml`

### 完整带注释示例

下方 `[crypto]` 下的数值是刻意不可用的脱敏占位符。真实的生效文件包含唯一的、生成的十六进制值。切勿将这些占位符值粘贴到设备中，也切勿替换可用文件中已存在的值。`[trust]` 与 `[device]` 的数值同样是示例；除非你打算更改上报的身份，否则请保留生效文件中的值。

```toml
# 配置格式。保持为 2。
version = 2

[main]
# 受支持的服务连接。保持此值不变。
backend = "injector"
# KeyMint 日志详细程度：off、error、warn、info、debug 或 trace。
log_level = "debug"
# 不安全的生物识别兼容开关。常规使用请保持 false。
force_skip_system_biometric_hat_verification = false

[crypto]
# 仅脱敏占位符。请保留生成的 64 字符值。
root_kek_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
kak_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_nonce = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# 可选的专家覆盖。通常让此行缺失。
# auth_token_hmac_key = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"

[trust]
# 每次 keymint 启动时检测 Android 主版本；使用整数可固定它。
os_version = "auto"
# 使用 auto、latest 或精确的 YYYY-MM-DD 日期；boot 也接受十进制 u32。
security_patch = "auto"
os_patchlevel = "auto"
vendor_patchlevel = "auto"
boot_patchlevel = "auto"
# 使用 auto、random 或恰好 64 个十六进制字符。
vb_key = "auto"
vb_hash = "auto"
# 为 true 时上报验证启动和已锁定引导加载程序。
verified_boot_state = true
device_locked = true

[device]
# 当应用请求证明 ID 时上报的设备身份字符串。
brand = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
device = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
product = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
manufacturer = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
model = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
serial = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# false 时仅在可用时从设备填充空的电话相关字段。
overrideTelephonyProperties = false
# 空的可选标识符是有效的；不要臆造缺失的值。
meid = ""
imei = ""
imei2 = ""
```

### 顶层字段

#### `version`

标识配置格式。支持的值为整数 `2`。它既不是 Android 版本，也不是 KOBING 发行号。不要递增它；当前文件应保持该值不变。热重载会拒绝其他值，并保留最后一个有效的运行时配置。

在 keymint 启动时，缺失的 `version` 会被视为 `0`。版本 `0` 和 `1` 会在服务启动前就地迁移为 `2`，并将 `os_version` 设为 `"auto"`，以便后续 Android 升级在下一次 keymint 启动时被检测到。启动还会移除过时的 `trust_record`。对于版本 `0`，缺失的补丁级别字段会继承已配置的 `security_patch`。其他已配置及未知的值会被保留。热重载期间不会执行迁移，因此请重启 keymint 以迁移较旧的文件。不受支持的未来版本绝不会被覆盖。

### `[main]`

#### `backend`

使用 `"injector"`。这是唯一受支持的用户选择，没有其他可选的运行时后端，因此该字段应保持不变。

#### `log_level`

控制 keymint 写入的消息。使用 `"off"`、`"error"`、`"warn"`、`"info"`、`"debug"` 或 `"trace"` 之一。`"debug"` 是默认值，也是提交错误报告时最有用的级别。`"trace"` 更为冗长；`"off"` 会抑制正常日志输出。

更改此字段需要重启 keymint。无法识别的值会回退到 `debug`，但依赖该回退可能会掩盖拼写错误。

#### `force_skip_system_biometric_hat_verification`

这是一个不安全的兼容开关，适用于系统 KeyMint 无法正确验证生物识别认证令牌的设备。当为 `true` 时，KOBING 会在不要求系统 KeyMint 验证其认证码的情况下，接受结构有效的令牌。

除非维护者在诊断已确认的设备特定问题，否则请保持 `false`。它并不隐藏 root，也不是指纹或锁屏故障的通用修复手段。有效保存后会应用到新的检查，无需重启 keymint。

### `[crypto]`

本节的每个值都是私密的。每个值恰好为 32 字节，以 64 个十六进制字符（使用 `0-9` 和 `a-f`）表示。KOBING 在创建新配置时会生成这些值。

请保持四个生成的种子与随机数字段都存在且稳定，并将其与 KOBING 数据一起私下备份。更改或移除其中任何一个都需要重启 keymint，并可能导致现有密钥或绑定认证的操作不可用。来自其他设备的值以及本指南中的脱敏占位符不能替代生效值。

如果缺少 `shared_secret_seed` 或 `shared_secret_nonce`，KOBING 在读取文件时会生成新的随机替代值。这并非稳定的生效配置，因此请确保两个生成值都保持存在。

#### `root_kek_seed`

该种子用于派生保护 KOBING 密钥 blob 的密钥材料。如果它变化，KOBING 可能无法再打开使用先前值创建的密钥。它必须存在且必须保持不变。

#### `kak_seed`

该种子用于 KOBING 的密钥协商保护。它属于与 `root_kek_seed` 相同的设备特定机密集合。它必须存在且必须保持不变。

#### `shared_secret_seed`

这是用于认证令牌验证的共享机密参数的种子部分。请将其与 `shared_secret_nonce` 一起保留；仅更改其中一半仍会改变最终的机密。

#### `shared_secret_nonce`

这是共享机密参数的随机数部分。它同样是完整的 64 字符十六进制值，不是短计数器，也不是需要手动重新生成的值。

#### `auth_token_hmac_key`

这个可选字段提供显式的认证令牌 HMAC 密钥。当它缺失时，KOBING 通过 `shared_secret_seed` 与 `shared_secret_nonce` 派生所需的密钥。普通用户应让该字段缺失。如果显式提供，它也必须恰好包含 64 个十六进制字符，并且必须保持私密和稳定。

### `[trust]`

这些字段控制通过密钥证明上报的值。它们不会修复硬件、续期证书、移除 keybox 吊销，也不会隐藏 root。

#### `os_version`

使用 `"auto"` 在每次 keymint 进程启动时检测当前 Android 主版本，或使用 `0` 到 `99` 的整数来固定一个主版本，例如 `12`、`16` 或 `17`。不要在此写入带点的版本号、SDK 号或安全补丁日期。KeyMint 使用 AOSP 的 `MMmmss` 公式对解析出的主版本进行编码，因此固定的 `16` 会上报为 `160000`。更改此字段需要重启 keymint。

#### `security_patch`

控制 `ro.build.version.security_patch`。它接受：

- `"auto"`：使用当前的 `ro.build.version.security_patch` 值而不写入它；
- `"latest"`：在解析该值时使用当前日历月的第五天；或
- 实际日期，写作 `"YYYY-MM-DD"`，包括前导零。

`"auto"` 首先使用非空的运行时属性，其次是来自标准 `build.prop` 位置的精确键，最后若两个来源都不可用则使用 `2025-06-05`。存在的运行时值会按原样使用，而不会被 `build.prop` 的值替换。`"latest"` 和精确日期会有意覆盖现有的运行时属性，但 KOBING 从不创建或删除它。`"auto"` 从不写入该属性。在一次显式或 `"latest"` 覆盖后，同一次启动中切换回 `"auto"` 会保留当前的运行时值；重启以恢复系统提供的值。

#### `os_patchlevel`

控制 KeyMint OS 补丁级别。`"auto"` 跟随生效的 `security_patch`；`"latest"` 和精确的 `"YYYY-MM-DD"` 日期会为 KeyMint 覆盖它，而不写入另一属性。最终值使用 AOSP 的 `YYYY-MM-DD` 解析器解析，并编码为 `YYYYMM`。

#### `vendor_patchlevel`

控制 KeyMint 供应商补丁级别。`"auto"` 首先读取非空的运行时 `ro.vendor.build.security_patch`，其次是来自标准 `build.prop` 位置的精确键，最后回退到生效的 `os_patchlevel`。`"latest"` 和精确的 `"YYYY-MM-DD"` 日期同样被接受。最终值使用 AOSP 的 `YYYY-MM-DD` 解析器解析，并编码为 `YYYYMMDD`。存在的非空来源不会仅因后续解析失败就被低优先级来源替换。KOBING 不写入供应商属性。

#### `boot_patchlevel`

控制 KeyMint 启动补丁级别。`"auto"` 首先从生效的顶层 vbmeta 镜像读取 `com.android.build.boot.security_patch`。如果该属性缺失，KOBING 会从生效启动镜像的独立 vbmeta 或 AVB 页脚内嵌 vbmeta 中读取同一属性，然后回退到启动头。旧式头字段存储年和月但不含日，因此其线上值以 `00` 结尾；全零字段因此变为 `20000000`，但仅在两个 vbmeta 位置均未提供该属性之后。如果启动元数据解析失败，KOBING 使用以下回退顺序：非空的运行时 `ro.vendor.boot_security_patch`、来自标准 `build.prop` 位置的精确键，然后是生效的 `os_patchlevel`。

`"latest"`、精确的 `"YYYY-MM-DD"` 日期以及十进制 `u32` 线上值同样被接受。十进制形式会保留诸如 `"20000000"` 的引导加载程序线上值，而不将其解释为日期。这些显式模式不会读取启动元数据。启动补丁级别解析不会读取系统 TEE 或写入启动属性。在热重载期间，未更改的 `"auto"` 会保留在 keymint 降权之前解析出的值；从覆盖切回 `"auto"` 会在 keymint 重启后生效。显式日期编码为 `YYYYMMDD`。如果选定的值无法转换，启动会失败；失败的热更新会保留先前的运行时配置。

当同一次保存中没有其他 `[trust]` 字段变化时，这四个补丁级别字段会在 keymint 运行期间一起解析并应用。现有 TA 会就地更新，以便进行中的操作和每次启动的计数器保持完好；等效的启动表示不会触发更新。如果对应的日志报告实时更新失败，请重启 keymint。

#### `vb_key`

控制 32 字节的验证启动公钥摘要：

- `"auto"` 首先读取 `ro.boot.vbmeta.public_key_digest`，然后尝试计算顶层 vbmeta 密钥摘要，仅当两个来源都不可用时才使用随机回退；
- `"random"` 在每次 keymint 启动时生成新值；或
- 64 字符的十六进制字符串固定一个精确值。

除非你了解所配置的证明配置，否则请保持 `"auto"`。更改此字段需要重启 keymint。如果 `"random"` 处于活动状态而你又将其改回 `"auto"`，请重启整个设备，以便 Android 在 `"auto"` 读取之前恢复原始启动属性。

#### `vb_hash`

控制 32 字节的验证启动哈希：

- `"auto"` 首先读取 `ro.boot.vbmeta.digest`，然后尝试原始系统证明哈希，仅当两个来源都不可用时才使用随机回退；
- `"random"` 在每次 keymint 启动时生成新值；或
- 64 字符的十六进制字符串固定一个精确值。

应用与 `vb_key` 相同的重启规则：正常更改后重启 keymint，从 `"random"` 返回 `"auto"` 时重启整个设备。

#### `verified_boot_state`

`true` 将验证启动状态上报为已验证；`false` 上报为未验证。这与 `device_locked` 开关相互独立。更改它需要重启 keymint。

#### `device_locked`

`true` 上报设备启动状态为已锁定；`false` 上报为未锁定。这并不会真正锁定或解锁引导加载程序。更改它需要重启 keymint。

### `[device]`

当应用显式请求证明 ID 时，本节提供设备身份字符串。这些值是个人数据。使用已为设备生成的值，并在更改本节后重启 keymint，以便重建一次性的证明 ID 快照。

#### `brand`

在证明 ID 请求中上报的产品品牌，创建新配置时通常基于 `ro.product.brand`。

#### `device`

在证明 ID 请求中上报的设备代号，通常基于 `ro.product.device`。

#### `product`

在证明 ID 请求中上报的产品名称，通常基于 `ro.product.name`。

#### `manufacturer`

在证明 ID 请求中上报的制造商名称，通常基于 `ro.product.manufacturer`。

#### `model`

在证明 ID 请求中上报的型号名称，通常基于 `ro.product.model`。

#### `serial`

在证明 ID 请求中上报的设备序列号，通常基于 `ro.serialno`。请将其视为私密信息，并在报告中脱敏。

#### `overrideTelephonyProperties`

在推荐值 `false` 下，KOBING 会尝试仅从设备的电话服务及属性回退中填充为空的 `imei`、`imei2` 和 `meid` 字段。已配置的非空值会被保留，并且 KOBING 会尝试将每个成功发现的值写回生效的 `config.toml`。

在 `true` 下，KOBING 会跳过电话发现，并完全按所写内容使用这三个已配置字段，包括空字符串。仅当你有意固定这些值时才使用它。

#### `imei`

主 IMEI。当设备没有 IMEI 或应由自动发现填充时，请将其留空。不要为满足某个应用而臆造值。

#### `imei2`

第二个 IMEI。单卡及部分双卡设备可以合法地让它为空。它的缺失不会使 `imei` 或非电话类设备字段失效。

#### `meid`

提供 MEID 的设备所使用的 MEID。许多设备没有 MEID，因此空值有效。它的缺失不会使可用的 IMEI 失效。

### `config.toml` 应用汇总

| 字段 | 所需操作 |
| --- | --- |
| `[main].log_level` | 重启 keymint。 |
| `[main].force_skip_system_biometric_hat_verification` | 有效保存后应用到新的检查。 |
| 所有 `[crypto]` 字段 | 重启 keymint；更改值可能导致密钥不可用。 |
| `[trust].security_patch`、`os_patchlevel`、`vendor_patchlevel`、`boot_patchlevel` | 当没有其他 `[trust]` 字段变化时作为一组热应用；否则重启 keymint。 |
| `[trust].os_version` | 重启 keymint。 |
| 其他 `[trust]` 字段 | 重启 keymint。 |
| 所有 `[device]` 字段 | 重启 keymint 以重建缓存的 ID 快照。 |
| `vb_key` 或 `vb_hash` 从 `"random"` 到 `"auto"` | 重启整个设备。 |

## `injector.toml`

### 完整带注释示例

```toml
# 配置格式。保持为 1。
version = 1

# 包名允许清单不再存储于此。它位于 bm.txt；其路径、格式与规则见下方
# bm.txt 一节。

[main]
# 请求路由的总开关。常规使用请保持 true。
enabled = true
# Injector 日志详细程度：off、error、warn、info、debug 或 trace。
log_level = "debug"

[filter]
# 强制执行 bm.txt 允许清单及下方安全规则。
enabled = true
# 即使另一个共享包被允许，也绝不使用 KOBING 的包。
deny_packages = []
# 阻止核心 Android 和系统身份。保持 true。
block_android_package = true
# 拒绝无法找到包名的调用方。保持 false。
allow_unknown_package = false

[intercept]
# 将被允许的调用方的每个具名 KeyStore 操作路由到 KOBING。
get_security_level = true
get_key_entry = true
update_subcomponent = true
list_entries = true
delete_key = true
grant = true
ungrant = true
get_number_of_entries = true
list_entries_batched = true
get_supplementary_attestation_info = true
```

### 顶层字段

#### `version`

标识 injector 配置格式。保持整数值 `1`。它既不是 Android 版本，也不是 KOBING 发行号。热重载会拒绝其他值，并保留最后一个有效的运行时配置。

在 injector 启动时，缺失的 `version` 会被视为 `0`，版本 `0` 会就地迁移为 `1`，同时保留文件的其余部分。版本 `0` 不会在热重载期间迁移，因此请重启 injector 以迁移此类文件。不受支持的未来版本绝不会被覆盖。

如果省略了某个已记录的 injector 字段，将使用其默认值。已记录的顶层及具名节中的未知字段会被拒绝，因此不要添加本指南未描述的字段名。

#### 包名允许清单

`injector.toml` 不再存储包名允许清单。可以使用 KOBING 的精确包名保存在一个单独的文件 `bm.txt` 中。其路径、格式与规则见下方 `bm.txt` 一节。

### `[main]`

#### `enabled`

这是 injector 的总路由开关。`true` 让过滤器与 `[intercept]` 设置决定每个新请求。`false` 会停止新的 KOBING 路由，使普通请求继续走系统。常规 KOBING 使用请保持 `true`。

避免在应用有密钥操作打开时更改此开关。保存更改，重启 injector，并在有意切换路由时重新打开应用。

#### `log_level`

控制 injector 消息。接受的值有 `"off"`、`"error"`、`"warn"`、`"warning"`、`"info"`、`"debug"` 和 `"trace"`；`"warning"` 是 `"warn"` 的别名。匹配不区分大小写，但推荐使用小写值。`"debug"` 是默认值，也是提交错误报告时的常规选择。

有效的文件更改会在不重启 injector 的情况下更新级别。无法识别的字符串不会使 TOML 文件失效；injector 会改用 `debug`。

### `[filter]`

在过滤器启用的情况下，KOBING 按以下顺序评估调用方：

1. 当 `block_android_package = true` 时，拒绝核心 Android 或系统身份。
2. 如果其包名无法解析，则遵循 `allow_unknown_package`。
3. 如果任何解析出的包在 `deny_packages` 中，则拒绝整个身份。
4. 如果其解析出的包均未列在 `bm.txt` 中，则拒绝它。
5. 否则允许其使用已启用的 `[intercept]` 路由。

对于共享同一 Android 身份的包，此顺序很重要：拒绝规则优先于 `bm.txt` 中的匹配条目。

在此常规过滤决策之后，`bm.txt` 一节所述的、KOBING 所属的窄范围授权例外，可为未知或超出范围的某个应用保留访问权限。它不会覆盖 Android 包阻止或 `deny_packages`。

#### `enabled`

`true` 强制执行 `bm.txt` 允许清单、拒绝清单、Android 包阻止以及未知包策略。`false` 会绕过全部四项检查，并允许每个调用方访问 `[intercept]` 下启用的任何操作。

禁用过滤器可能将 Android 服务及无关应用路由到 KOBING，并可能破坏解锁、应用存储或用户界面。请保持 `true`。

#### `deny_packages`

这是一个精确包名的数组，这些包不得使用 KOBING。当某个已选包与另一个必须留在系统的包共享其 Android 身份时，它很有用。如果为该身份解析出的任一包被拒绝，则整个身份都会被拒绝，即使另一个包已列在 `bm.txt` 中。

空数组 `[]` 是默认值。该列表使用带引号、逗号分隔的 TOML 语法；它与单独的 `bm.txt` 允许清单无关。

#### `block_android_package`

`true` 在考虑 `bm.txt` 之前就拒绝核心 Android 和系统身份。它还会拒绝解析出的包名等于 `android` 或以 `android.` 开头的调用方。这并不意味着每个名称以 `com.android.` 开头的普通应用都会被自动阻止。

请保持此设置为 `true`。将其设为 `false` 只是移除了这项安全检查；其余过滤规则仍然适用。

#### `allow_unknown_package`

控制 Android 包名无法解析的调用方。`false` 拒绝该调用方，这是安全的默认值。`true` 允许未解析的应用身份而无需在 `bm.txt` 中匹配；当 `block_android_package = true` 时，核心 Android 身份仍会被拒绝。

此设置不是"所有应用"开关。除非维护者已确认某个受支持的应用无法正常解析，否则请保持 `false`。

### `[intercept]`

每个开关控制一个 Android KeyStore 服务操作。对于被过滤器允许的调用方，`true` 将该操作路由到 KOBING，`false` 将该操作留在系统上。这些开关不会迁移现有密钥，也不会使系统创建的密钥引用可被 KOBING 使用。

KOBING 所属的授权例外与普通包路由相互独立。带有已确认 KOBING 授权的请求，即使接收应用在 `bm.txt` 允许清单之外，仍可返回 KOBING，从而使已授权的密钥保持可用。

常规使用请保持所有开关为 `true`。对同一应用混用系统与 KOBING 操作可能导致密钥缺失错误、列表不一致或后续操作失败。

#### `get_security_level`

控制对 TEE 或 StrongBox KeyStore 安全级别句柄的请求。应用将该句柄用于后续操作，如创建、导入和使用密钥。

#### `get_key_entry`

控制对现有密钥条目的检索，包括其元数据及用于后续密钥操作的句柄。

#### `update_subcomponent`

控制替换现有密钥条目的证书或证书链组件。

#### `list_entries`

控制列出所请求命名空间中的密钥别名。

#### `delete_key`

控制删除具名密钥。选定的后端具有权威性；KOBING 不会删除匹配的系统密钥作为替代。

#### `grant`

控制授予另一个应用访问某密钥的权限。

#### `ungrant`

控制移除先前授予的密钥权限。

#### `get_number_of_entries`

控制统计命名空间中的密钥条目数。

#### `list_entries_batched`

控制密钥条目的分页或批量列出。

#### `get_supplementary_attestation_info`

控制检索受支持的证明请求所使用的补充信息。

### 按包划分的子表

诸如 `[scoop.com.example.app]` 的按包划分的表，以及诸如 `mode = "strict"` 的值，都不是受支持的路由选项。它们在文件被解析时可能被保留，但不会改变由哪个后端处理请求。不要添加它们；允许清单请使用 `bm.txt`，路由请使用 `[filter]` 和 `[intercept]`。

### `injector.toml` 应用汇总

每个有效的已记录字段更改都会应用到新请求，无需重启设备。对于 `bm.txt` 允许清单、`[main].enabled`、`[filter]` 或 `[intercept]` 的更改，当你需要在路由变化后获得清晰边界时，请重启 injector 并重新打开受影响的应用。语法错误、未知字段或不受支持的未来 `version` 会让最后一个有效的运行时配置保持生效；如果它们在 injector 启动时存在，则会使 KOBING 请求路由保持禁用，直到文件被修正。


## `bm.txt`

`bm.txt` 列出可以使用 KOBING 的精确 Android 包名。它取代了原先位于 `injector.toml` 内的 `scoop` 数组。

### 路径

- 运行时实体：`/data/surprise/bm.txt`

injector 直接读取该实体路径。

### 格式

- 每行一个包名，例如 `com.example.app`。
- 空行以及第一个非空格字符为 `#` 的行会被忽略。
- 首尾空格会被去除，重复条目会合并为一条。
- 不接受应用标签、部分名称或通配符。

在模块安装时以及每次启动时，如果文件缺失，模块会从打包的默认列表生成 `bm.txt`，然后将所有权修正为 `keystore`、权限修正为 `0644`。编辑该文件会应用到新请求，无需重启；当你需要清晰的路由边界时，请重启 injector 并重新打开受影响的应用。

### 默认内容

```text
io.github.vvb2060.keyattestation
com.google.android.gsf
com.google.android.gms
com.android.vending
com.eltavine.duckdetector
```

Android 可以为多个包分配同一身份。在这种情况下，只要列出其中任何一个包，就允许该共享身份，除非某条过滤规则拒绝了该组中的某个包。添加或移除某个包不会在系统与 KOBING 之间移动或转换密钥；应用可能失去对通过另一条路由创建的密钥的访问权限。

存在一个窄范围的已授权密钥例外。位于 `bm.txt` 之外的应用，或其包名无法解析的应用，仍可使用 KOBING 确认属于某个 KOBING 密钥的密钥访问授权。这样可使由另一应用刻意共享的密钥保持可用，而不授予接收应用通用的 KOBING 访问权限。被 Android 阻止及被拒绝清单列出的调用方不会获得此例外。
