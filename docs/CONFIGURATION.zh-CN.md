# 配置指南

[English](CONFIGURATION.md) | **简体中文** | [繁體中文](CONFIGURATION.zh-TW.md)

KoBing（KOBING）一共用三个配置文件：

- `/data/surprise/waste/config.toml`——管 KeyMint 服务本身、它对外报的身份，还有给 KOBING 创建的密钥用的那些机密。
- `/data/surprise/injector.toml`——决定哪些 KeyStore 请求转到 KOBING。
- `/data/surprise/bm.txt`——哪些应用能用 KOBING，名单就在这。

这份指南写的就是你设备上当前生效的配置。示例后面还跟着一套单独的逐字段说明，所以示例里的注释不全没关系，细节以字段说明为准。

**跳转：** [`config.toml`](#configtoml) | [`injector.toml`](#injectortoml) | [`bm.txt`](#bmtxt)

## 编辑之前

日常用的话，基本只动一个地方就够了：`bm.txt` 里的包名。`injector.toml`、安全过滤、`[intercept]` 那一堆开关，还有生成出来的 `[crypto]` 值，都别碰。

改之前先做三件事：

1. 把生效中的文件私下备份一份。
2. 改的是 `/data/surprise/`（以及 `/data/surprise/waste/`）里的文件，不是模块 ZIP 里那份。
3. 字符串照旧带引号，布尔值就写 `true` / `false`；包名写进 `bm.txt`，一行一个、写全名。

一次只改一处，改完把整个文件存下来，然后看一眼对应的日志。

`[crypto]` 的值、IMEI、IMEI2、MEID、序列号，还有任何没脱敏的配置副本，都别往外发。

## 改动如何被加载

两个组件都会盯着自己的生效文件，但行为不一样：

- `injector.toml` 和 `bm.txt` 的有效改动直接对新请求生效，不用重启。
- `config.toml` 会被自动读取，但真正不用重启 keymint 就能完全生效的，只有那四个补丁级别字段和生物识别兼容开关。其余什么时候要重启，下面每个字段都写了。
- 组件跑着的时候，存了格式错的文件会被直接拒掉，内存里最后一份有效配置继续用。
- keymint 启动时如果 `config.toml` 是坏的，它起不来。修好文件，重启 keymint。
- injector 启动时如果 `injector.toml` 是坏的，KOBING 路由会一直关着。存一份有效文件，监视器自己会把路由接回来；实在恢复不了才重启 injector。
- 启动时哪个文件不见了，KOBING 会用默认值新建一个。别拿这个当"恢复出厂"用——重新生成的机密救不回原来那些密钥。

重启命令见[重启 keymint 与 injector](../README.zh-CN.md#重启-keymint-与-injector)。改完路由，记得把受影响的应用关掉再打开，免得半路打开的操作跟新路由打架。真想要个干净的边界，重启 injector 就够了；只改 injector 相关的设置，不用重启 keymint。

## `config.toml`

### 完整带注释示例

下面 `[crypto]` 里的值是故意写坏的占位符，没有实际用处。你设备上真正生效的文件里，是各自唯一的十六进制值。这些占位符别往设备里贴，也别拿去覆盖文件里已经有的值。`[trust]` 和 `[device]` 的值同样只是示例——除非你确实想改上报的身份，不然保留生效文件里的原值就行。

```toml
# 配置格式，固定为 2。
version = 2

[main]
# 服务连接方式。别改。
backend = "injector"
# KeyMint 日志级别：off、error、warn、info、debug、trace。
log_level = "debug"
# 不安全的生物识别兼容开关。正常用保持 false。
force_skip_system_biometric_hat_verification = false

[crypto]
# 只是脱敏占位符。真实的 64 字符值要留着。
root_kek_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
kak_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_nonce = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# 专家才需要动的覆盖项。通常直接删掉这行。
# auth_token_hmac_key = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"

[trust]
# 每次 keymint 启动时自动探测 Android 主版本；写整数可以钉死。
os_version = "auto"
# 可选 auto、latest，或精确的 YYYY-MM-DD；boot 也收十进制 u32。
security_patch = "auto"
os_patchlevel = "auto"
vendor_patchlevel = "auto"
boot_patchlevel = "auto"
# 可选 auto、random，或正好 64 个十六进制字符。
vb_key = "auto"
vb_hash = "auto"
# 为 true 时上报已验证启动、引导加载程序已锁定。
verified_boot_state = true
device_locked = true

[device]
# 应用要证明 ID 时上报的设备身份字符串。
brand = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
device = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
product = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
manufacturer = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
model = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
serial = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# 为 false 时，空的电话字段只在能从设备拿到值时填充。
overrideTelephonyProperties = false
# 可选的标识符空着是合法的，别硬编。
meid = ""
imei = ""
imei2 = ""
```

### 顶层字段

#### `version`

配置格式版本，只能是整数 `2`。它跟 Android 版本、KOBING 版本号都没关系。别往上加，当前文件保持这个值就行。写别的值热重载会拒绝，继续沿用最后一份有效的运行时配置。

keymint 启动时如果缺 `version`，按 `0` 处理。`0` 和 `1` 会在服务启动前就地升到 `2`，同时把 `os_version` 设成 `"auto"`，这样以后升级 Android，下次 keymint 启动就能识别出来。启动时还会顺手删掉过时的 `trust_record`。版本 `0` 如果缺补丁级别字段，会继承已经配置的 `security_patch`；其他已配置的和未知的值都原样留着。热重载不做迁移，想把老文件升级就得重启 keymint。未来那种不认识的版本，绝不会被覆盖。

### `[main]`

#### `backend`

就写 `"injector"`。这是唯一支持的选择，没有别的运行时后端，别改。

#### `log_level`

决定 keymint 往外打什么日志。可选 `"off"`、`"error"`、`"warn"`、`"info"`、`"debug"`、`"trace"`。默认 `"debug"`，提 bug 报告时也用它最合适。`"trace"` 话更多，`"off"` 直接把正常日志全关掉。

改这个要重启 keymint。认不出的值会退回 `debug`，但别指望它，容易把拼写错误盖过去。

#### `force_skip_system_biometric_hat_verification`

一个不安全的兼容开关，专门给那些系统 KeyMint 验不好生物识别令牌的设备用。开成 `true`，KOBING 就不要求系统 KeyMint 校验认证码了，令牌结构没问题就认。

除非维护者确认是某个设备特有的毛病，否则一直保持 `false`。它不负责藏 root，也不是指纹、锁屏出问题的万能药。存成有效值后对新检查立刻生效，不用重启 keymint。

### `[crypto]`

这一节每个值都是机密。每个值正好 32 字节，写成 64 个十六进制字符（`0-9`、`a-f`）。新建配置时 KOBING 会自己生成。

四个种子和随机数字段，要一直留着、别改动，跟着 KOBING 的数据一起私下备份好。改了或删了任何一个，都得重启 keymint，而且很可能导致已有的密钥、或者绑定了认证的操作直接不可用。别拿别的设备上的值，也别拿本文档里的占位符来顶替。

`shared_secret_seed` 或 `shared_secret_nonce` 如果缺了，KOBING 读文件时会重新随机生成一批。那就不算稳定的生效配置了，所以这两个值务必都在。

#### `root_kek_seed`

用来派生保护 KOBING 密钥 blob 的密钥材料。它一变，那些用旧值创建的密钥 KOBING 可能就打不开了。必须有，而且不能变。

#### `kak_seed`

KOBING 密钥协商保护用的种子，跟 `root_kek_seed` 属于同一套设备机密。必须有，不能变。

#### `shared_secret_seed`

认证令牌校验所用共享机密的种子部分。要跟 `shared_secret_nonce` 成对保留——只改一半，最终的机密照样变。

#### `shared_secret_nonce`

共享机密的随机数部分。同样是完整的 64 字符十六进制值，不是什么短计数器，也不用你手动重算。

#### `auth_token_hmac_key`

可选的显式认证令牌 HMAC 密钥。不写这个字段时，KOBING 会用 `shared_secret_seed` 加 `shared_secret_nonce` 自己推出来。普通用户直接别写这行。真要显式给，也得正好 64 个十六进制字符，同样得保密、不能变。

### `[trust]`

这一节管的是密钥证明里上报出去的那些值。它不会修硬件、不会续证书、不会解除 keybox 吊销，也不负责藏 root。

#### `os_version`

写 `"auto"` 就每次 keymint 进程启动时自己探测当前 Android 主版本；也可以写 `0` 到 `99` 的整数钉死一个，比如 `12`、`16`、`17`。别在这里写带点的版本号、SDK 号或者安全补丁日期。KeyMint 按 AOSP 的 `MMmmss` 公式编码解析出的主版本，所以钉住的 `16` 上报出去是 `160000`。改这个要重启 keymint。

#### `security_patch`

管的是 `ro.build.version.security_patch`。取值：

- `"auto"`：沿用当前的 `ro.build.version.security_patch`，不改写；
- `"latest"`：解析时取当前日历月的 5 号；
- 具体日期，写成 `"YYYY-MM-DD"`，要带前导零。

`"auto"` 的取值顺序是：先用运行时属性里非空的值，再找标准 `build.prop` 位置里的精确键，两个都没有才用 `2025-06-05`。运行时里已经有的值会原样用，不会被 `build.prop` 的值顶替。`"latest"` 和精确日期是刻意覆盖运行时属性的，但 KOBING 从不会创建或删掉它。`"auto"` 从不写这个属性。同一次启动里，先显式覆盖或用了 `"latest"`，再切回 `"auto"`，会保留当前运行时值；想要系统原本的值只能重启。

#### `os_patchlevel`

管 KeyMint 的 OS 补丁级别。`"auto"` 跟着生效的 `security_patch` 走；`"latest"` 和精确的 `"YYYY-MM-DD"` 会单独给 KeyMint 覆盖，不写别的属性。最终值走 AOSP 的 `YYYY-MM-DD` 解析器，编码成 `YYYYMM`。

#### `vendor_patchlevel`

管 KeyMint 的供应商补丁级别。`"auto"` 先读运行时非空的 `ro.vendor.build.security_patch`，再找标准 `build.prop` 里的精确键，都没有就退回生效的 `os_patchlevel`。`"latest"` 和精确日期同样可以用。最终值走 AOSP 的 `YYYY-MM-DD` 解析器，编码成 `YYYYMMDD`。来源里如果已经有非空值，不会因为后面解析失败就被优先级更低的东西顶掉。KOBING 不写供应商属性。

#### `boot_patchlevel`

管 KeyMint 的启动补丁级别。`"auto"` 先从生效的顶层 vbmeta 镜像读 `com.android.build.boot.security_patch`。这个属性要是没有，KOBING 会去生效启动镜像里独立的 vbmeta、或者 AVB 页脚内嵌的 vbmeta 里找同一个属性，再不行才看启动头。旧式头字段只存年月、没有日，所以线上值末尾是 `00`；全零字段因此会变成 `20000000`——但这只有在前两个 vbmeta 位置都没给出该属性时才会发生。启动元数据解析失败的话，回退顺序是：运行时非空的 `ro.vendor.boot_security_patch` → 标准 `build.prop` 里的精确键 → 生效的 `os_patchlevel`。

`"latest"`、精确的 `"YYYY-MM-DD"`，还有十进制 `u32` 线上值也都收。十进制能保留像 `"20000000"` 这种引导加载程序线上值，不把它当日期解释。这几种显式写法都不会去读启动元数据。启动补丁级别解析既不看系统 TEE，也不写启动属性。热重载时，没动过的 `"auto"` 会保住 keymint 降权之前解析到的那份值；从覆盖切回 `"auto"` 则要等 keymint 重启才生效。显式日期编码成 `YYYYMMDD`。选出来的值转不了的话，启动会失败；热更新失败就继续用先前的运行时配置。

这四个补丁级别字段，在同一次保存里没有别的 `[trust]` 字段一起变时，会在 keymint 运行期间一起解析、一起应用。现有 TA 就地更新，正在进行的操作和每次启动的计数器都不受影响；表示形式上没有实质变化的不会触发更新。要是日志说实时更新失败，就重启 keymint。

#### `vb_key`

管 32 字节的验证启动公钥摘要：

- `"auto"`：先读 `ro.boot.vbmeta.public_key_digest`，读不到就试着算顶层 vbmeta 的密钥摘要，两个都不行才用随机值兜底；
- `"random"`：每次 keymint 启动都生成新的；
- 64 字符十六进制串：钉死某个确切值。

除非你清楚自己在配什么证明，不然保持 `"auto"`。改这个要重启 keymint。要是 `"random"` 正开着、你想切回 `"auto"`，得整机重启，让 Android 先把原始启动属性恢复出来，`"auto"` 才读得到。

#### `vb_hash`

管 32 字节的验证启动哈希：

- `"auto"`：先读 `ro.boot.vbmeta.digest`，读不到就试原始系统证明哈希，两个都不行才用随机值兜底；
- `"random"`：每次 keymint 启动都生成新的；
- 64 字符十六进制串：钉死某个确切值。

重启规则跟 `vb_key` 一样：正常改完重启 keymint，从 `"random"` 回 `"auto"` 要整机重启。

#### `verified_boot_state`

`true` 表示上报"已验证启动"，`false` 表示"未验证"。跟 `device_locked` 各管各的。改它要重启 keymint。

#### `device_locked`

`true` 表示上报设备已锁定，`false` 表示未锁定。它并不会真的去锁/解锁引导加载程序。改它要重启 keymint。

### `[device]`

应用明确要证明 ID 时，这一节提供设备身份字符串。这些都是个人数据。用设备上已经生成好的值；改完这一节要重启 keymint，好把一次性的证明 ID 快照重建一遍。

#### `brand`

证明 ID 请求里上报的品牌，新建配置时一般取自 `ro.product.brand`。

#### `device`

证明 ID 请求里上报的设备代号，一般取自 `ro.product.device`。

#### `product`

证明 ID 请求里上报的产品名，一般取自 `ro.product.name`。

#### `manufacturer`

证明 ID 请求里上报的制造商，一般取自 `ro.product.manufacturer`。

#### `model`

证明 ID 请求里上报的型号，一般取自 `ro.product.model`。

#### `serial`

证明 ID 请求里上报的序列号，一般取自 `ro.serialno`。当私密信息对待，发报告前记得打码。

#### `overrideTelephonyProperties`

推荐值 `false`。这时 KOBING 会尝试从设备的电话服务和属性回退里，把空着的 `imei`、`imei2`、`meid` 填上。已经配好的非空值会被保留；每成功找到一个值，KOBING 还会试着写回生效的 `config.toml`。

设成 `true`，KOBING 就跳过电话发现，这三个字段完全照你写的来（包括空字符串）。只有你确实想钉死这几个值时才用它。

#### `imei`

主 IMEI。设备没有 IMEI，或者本来就该自动填的，就留空。别为了让某个应用满意硬编一个。

#### `imei2`

第二个 IMEI。单卡设备、还有一些双卡设备，留空很正常。它空着不影响 `imei`，也不影响其他非电话字段。

#### `meid`

有 MEID 的设备才用。很多设备本来就没有 MEID，空着没问题。它空着不会让可用的 IMEI 失效。

### `config.toml` 应用汇总

| 字段 | 要做什么 |
| --- | --- |
| `[main].log_level` | 重启 keymint。 |
| `[main].force_skip_system_biometric_hat_verification` | 有效保存后对新检查生效。 |
| 所有 `[crypto]` 字段 | 重启 keymint；改值可能让密钥不可用。 |
| `[trust].security_patch`、`os_patchlevel`、`vendor_patchlevel`、`boot_patchlevel` | 没有别的 `[trust]` 字段一起变时，作为一组热应用；否则重启 keymint。 |
| `[trust].os_version` | 重启 keymint。 |
| 其他 `[trust]` 字段 | 重启 keymint。 |
| 所有 `[device]` 字段 | 重启 keymint，重建缓存的 ID 快照。 |
| `vb_key` 或 `vb_hash` 从 `"random"` 改回 `"auto"` | 整机重启。 |

## `injector.toml`

### 完整带注释示例

```toml
# 配置格式，固定为 1。
version = 1

# 包名名单不在这了。它挪到了 bm.txt，路径、格式和规则见下面
# bm.txt 那一节。

[main]
# 路由总开关。正常用保持 true。
enabled = true
# Injector 日志级别：off、error、warn、info、debug、trace。
log_level = "debug"

[filter]
# 是否执行 bm.txt 名单和下面的安全规则。
enabled = true
# 就算某个共享包被允许了，这些包也绝不用 KOBING。
deny_packages = []
# 拦掉核心 Android 和系统身份。保持 true。
block_android_package = true
# 包名解析不出来的调用方，是否拒绝。保持 false。
allow_unknown_package = false

[intercept]
# 被允许的调用方，它的每个具名 KeyStore 操作是否转到 KOBING。
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

injector 的配置格式版本，保持整数 `1`。跟 Android 版本、KOBING 版本号无关。热重载会拒绝别的值，继续用最后一份有效运行时配置。

injector 启动时缺 `version` 就按 `0` 算，`0` 会就地升到 `1`，文件其余部分不动。热重载不做这个升级，所以要升这种文件得重启 injector。未来不认识的版本绝不会被覆盖。

文档里写到的字段如果没写，用默认值。顶层和具名节里那些没记录的未知字段会被拒，所以别加本文档没讲的字段名。

#### 包名允许清单

`injector.toml` 不再存包名名单了。能用的精确包名单独放在 `bm.txt`。路径、格式和规则见下面 `bm.txt` 一节。

### `[main]`

#### `enabled`

injector 的总路由开关。`true` 时，每个新请求交给过滤器和 `[intercept]` 决定。`false` 就不再往 KOBING 路由，普通请求照旧走系统。正常用 KOBING 就保持 `true`。

应用还开着密钥操作的时候，别去动这个开关。保存改动、重启 injector，要切路由就把应用重新打开。

#### `log_level`

管 injector 的日志。可选 `"off"`、`"error"`、`"warn"`、`"warning"`、`"info"`、`"debug"`、`"trace"`，其中 `"warning"` 是 `"warn"` 的别名。匹配不分大小写，不过建议写小写。默认 `"debug"`，提 bug 报告一般也用它。

有效改动不用重启 injector 就能换级别。认不出的字符串不会让 TOML 文件失效，injector 会退回 `debug`。

### `[filter]`

过滤器开着时，KOBING 按这个顺序判断调用方：

1. `block_android_package = true` 时，先拒掉核心 Android 或系统身份。
2. 包名解析不出来的，看 `allow_unknown_package`。
3. 解析出的包里有任何一个在 `deny_packages` 里，整个身份都拒。
4. 解析出的包一个都不在 `bm.txt` 里，拒掉。
5. 以上都没问题，就放它走已启用的 `[intercept]` 路由。

几个包共享同一个 Android 身份时，顺序就很关键：拒绝规则优先于 `bm.txt` 里的匹配。

常规过滤判断之后，还有 `bm.txt` 一节讲的那个窄范围授权例外，能给某个未知或范围外的应用留条访问权限。它不会推翻 Android 包拦截或 `deny_packages`。

#### `enabled`

`true` 会真正执行 `bm.txt` 名单、拒绝名单、Android 包拦截和未知包策略。`false` 就跳过这四项检查，任何调用方都能访问 `[intercept]` 里开着的操作。

关掉过滤器可能把 Android 服务、还有一堆无关应用都路由到 KOBING，进而搞坏解锁、应用存储或者界面。保持 `true`。

#### `deny_packages`

一个精确包名数组，里面的包不许用 KOBING。某个包被选中、又跟另一个必须留在系统的包共享 Android 身份时，这个就有用。该身份解析出的包只要有一个被拒，整个身份都拒，哪怕另一个包已经写在 `bm.txt` 里。

默认是空数组 `[]`。列表用带引号、逗号分隔的 TOML 语法，跟单独的 `bm.txt` 名单互不相干。

#### `block_android_package`

`true` 时，还没轮到看 `bm.txt` 就把核心 Android 和系统身份拒了；解析出的包名等于 `android`、或者以 `android.` 开头的调用方也会被拒。注意，这不代表名字以 `com.android.` 开头的普通应用会被一并拦掉。

保持 `true`。设成 `false` 只是把这道安全检查拿掉了，其余过滤规则照旧。

#### `allow_unknown_package`

管的是 Android 包名解析不出来的调用方。`false` 直接拒，这是稳妥的默认值。`true` 就允许身份不明、又没在 `bm.txt` 里匹配上的应用；不过 `block_android_package = true` 时，核心 Android 身份还是会被拒。

它不是"通吃所有应用"的开关。除非维护者确认某个支持的应用死活解析不出来，否则保持 `false`。

### `[intercept]`

每个开关对应一个 Android KeyStore 服务操作。对过滤器放行的调用方，`true` 就把该操作转到 KOBING，`false` 就留在系统里。这些开关不会迁移已有密钥，也不会让系统创建的密钥引用变成 KOBING 能用。

KOBING 那个授权例外跟普通包路由是两码事。请求带着已确认的 KOBING 授权，就算接收应用不在 `bm.txt` 名单里，照样能回到 KOBING，被授权的密钥就还能用。

正常用就全部保持 `true`。同一个应用混着走系统和 KOBING，容易出现密钥找不到、列表对不上或者后续操作失败。

#### `get_security_level`

管对 TEE 或 StrongBox 安全级别句柄的请求。应用拿到这个句柄，后面才有创建、导入、使用密钥这些操作。

#### `get_key_entry`

管取回已有密钥条目，包括它的元数据和后续操作用的句柄。

#### `update_subcomponent`

管替换已有密钥条目的证书或证书链组件。

#### `list_entries`

管列出所请求命名空间里的密钥别名。

#### `delete_key`

管删除具名密钥。选中的后端说了算；KOBING 不会顺手删掉对应的系统密钥来顶替。

#### `grant`

管把某个密钥的访问权限授予另一个应用。

#### `ungrant`

管撤销之前授予的密钥权限。

#### `get_number_of_entries`

管统计命名空间里的密钥条目数。

#### `list_entries_batched`

管密钥条目的分页或批量列出。

#### `get_supplementary_attestation_info`

管取回受支持证明请求要用的补充信息。

### 按包划分的子表

`[scoop.com.example.app]` 这类按包划分的表，还有 `mode = "strict"` 这类值，都不是支持的路由选项。文件解析时它们可能被留着，但不会改变哪个后端处理请求。别加它们：名单用 `bm.txt`，路由用 `[filter]` 和 `[intercept]`。

### `injector.toml` 应用汇总

每个已记录字段的有效改动都会对新请求生效，不用重启设备。改的是 `bm.txt` 名单、`[main].enabled`、`[filter]` 或 `[intercept]`，想要路由变化后有个干净边界，就重启 injector 并把受影响的应用重新打开。语法错误、未知字段，或者未来不支持的 `version`，会让最后一份有效运行时配置继续生效；如果这些在 injector 启动时就存在，KOBING 路由会一直关着，直到文件修好。

## `bm.txt`

`bm.txt` 里是可以使用 KOBING 的精确 Android 包名。它取代了原先放在 `injector.toml` 里的 `scoop` 数组。

### 路径

- 运行时实体：`/data/surprise/bm.txt`

injector 直接读这个实体路径。

### 格式

- 一行一个包名，比如 `com.example.app`。
- 空行、以及第一个非空字符是 `#` 的行，忽略。
- 首尾空格去掉，重复的合并成一条。
- 不支持应用标签、部分名称或通配符。

模块安装时、以及每次启动时，文件不在的话，模块会用打包的默认列表生成 `bm.txt`，然后把属主改成 `keystore`、权限改成 `0644`。改这个文件对新请求立即生效，不用重启；想要清晰的路由边界，就重启 injector 并重新打开受影响的应用。

### 默认内容

```text
io.github.vvb2060.keyattestation
com.google.android.gsf
com.google.android.gms
com.android.vending
com.eltavine.duckdetector
```

Android 允许几个包共用一个身份。这种情况下列出任一包就放行整个身份，除非某条过滤规则拒了这组里的某个包。增删某个包，并不会在系统和 KOBING 之间搬密钥或转密钥；应用可能因此打不开之前用另一条路由创建的密钥。

还有一个窄范围的已授权密钥例外。不在 `bm.txt` 里的应用、或者包名解析不出来的应用，仍然可以用 KOBING 去确认某个 KOBING 密钥的访问授权。这样别的应用主动共享出来的密钥还能继续用，同时又不会把 KOBING 的通用访问权给接收方。被 Android 拦掉的、以及被拒绝名单点名的调用方，拿不到这个例外。
