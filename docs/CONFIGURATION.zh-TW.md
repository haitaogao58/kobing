# 配置指南

[English](CONFIGURATION.md) | [简体中文](CONFIGURATION.zh-CN.md) | **繁體中文**

KoBing（KOBING）一共用三個設定檔：

- `/data/surprise/waste/config.toml`——管 KeyMint 服務本身、它對外報的身份，還有給 KOBING 建立的密鑰用的那些密文。
- `/data/surprise/injector.toml`——決定哪些 KeyStore 請求轉到 KOBING。
- `/data/surprise/bm.txt`——哪些應用能用 KOBING，名單就在這。

這份指南寫的就是你裝置上目前生效的設定。範例後面還跟著一套分開的逐欄位說明，所以範例裡的註解不全沒關係，細節以欄位說明為準。

**跳轉：** [`config.toml`](#configtoml) | [`injector.toml`](#injectortoml) | [`bm.txt`](#bmtxt)

## 編輯之前

日常用的話，基本上只動一個地方就夠了：`bm.txt` 裡的包名。`injector.toml`、安全過濾、`[intercept]` 那一堆開關，還有生成出來的 `[crypto]` 值，都別碰。

改之前先做三件事：

1. 把生效中的檔案私下備份一份。
2. 改的是 `/data/surprise/`（以及 `/data/surprise/waste/`）裡的檔案，不是模組 ZIP 裡那份。
3. 字串照舊帶引號，布林值就寫 `true` / `false`；包名寫進 `bm.txt`，一行一個、寫全名。

一次只改一處，改完把整個檔案存下來，然後看一下對應的日誌。

`[crypto]` 的值、IMEI、IMEI2、MEID、序號，還有任何沒脫敏的設定副本，都別往外傳。

## 改動如何被加載

兩個元件都會盯著自己的生效檔案，但行為不一樣：

- `injector.toml` 和 `bm.txt` 的有效改動直接對新請求生效，不用重啟。
- `config.toml` 會被自動讀取，但真正不用重啟 keymint 就能完全生效的，只有那四個補丁級別欄位和生物識別相容開關。其餘什麼時候要重啟，下面每個欄位都寫了。
- 元件跑著的時候，存了格式錯的檔案會被直接拒掉，記憶體裡最後一份有效設定繼續用。
- keymint 啟動時如果 `config.toml` 是壞的，它起不來。修好檔案，重啟 keymint。
- injector 啟動時如果 `injector.toml` 是壞的，KOBING 路由會一直關著。存一份有效檔案，監視器自己會把路由接回來；真的恢復不了才重啟 injector。
- 啟動時哪個檔案不見了，KOBING 會用預設值新建一個。別拿這個當「恢復出廠」用——重新生成的密文救不回原來那些密鑰。

重啟指令見[重啟 keymint 與 injector](../README.zh-TW.md#重啟-keymint-與-injector)。改完路由，記得把受影響的應用關掉再打開，免得半路打開的操作跟新路由打架。真想要個乾淨的邊界，重啟 injector 就夠了；只改 injector 相關的設定，不用重啟 keymint。

## `config.toml`

### 完整帶註釋示例

下面 `[crypto]` 裡的值是故意寫壞的佔位符，沒有實際用處。你裝置上真正生效的檔案裡，是各自唯一的十六進位值。這些佔位符別往裝置裡貼，也別拿去覆蓋檔案裡已經有的值。`[trust]` 和 `[device]` 的值同樣只是範例——除非你確實想改上報的身份，不然保留生效檔案裡的原值就行。

```toml
# 設定格式，固定為 2。
version = 2

[main]
# 服務連線方式。別改。
backend = "injector"
# KeyMint 日誌級別：off、error、warn、info、debug、trace。
log_level = "debug"
# 不安全的生物識別相容開關。正常用保持 false。
force_skip_system_biometric_hat_verification = false

[crypto]
# 只是脫敏佔位符。真實的 64 字元值要留著。
root_kek_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
kak_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_nonce = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# 專家才需要動的覆寫項。通常直接刪掉這行。
# auth_token_hmac_key = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"

[trust]
# 每次 keymint 啟動時自動偵測 Android 主版本；寫整數可以釘死。
os_version = "auto"
# 可選 auto、latest，或精確的 YYYY-MM-DD；boot 也收十進位 u32。
security_patch = "auto"
os_patchlevel = "auto"
vendor_patchlevel = "auto"
boot_patchlevel = "auto"
# 可選 auto、random，或剛好 64 個十六進位字元。
vb_key = "auto"
vb_hash = "auto"
# 為 true 時上報已驗證啟動、引導載入程式已鎖定。
verified_boot_state = true
device_locked = true

[device]
# 應用要證明 ID 時上報的裝置身份字串。
brand = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
device = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
product = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
manufacturer = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
model = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
serial = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# 為 false 時，空的電話欄位只在能從裝置拿到值時填充。
overrideTelephonyProperties = false
# 可選的識別碼空著是合法的，別硬編。
meid = ""
imei = ""
imei2 = ""
```

### 頂層字段

#### `version`

設定格式版本，只能是整數 `2`。它跟 Android 版本、KOBING 版本號都沒關係。別往上加，目前檔案保持這個值就行。寫別的值熱重載會拒絕，繼續沿用最後一份有效的執行時設定。

keymint 啟動時如果缺 `version`，按 `0` 處理。`0` 和 `1` 會在服務啟動前就地升到 `2`，同時把 `os_version` 設成 `"auto"`，這樣以後升級 Android，下次 keymint 啟動就能認出來。啟動時還會順手刪掉過時的 `trust_record`。版本 `0` 如果缺補丁級別欄位，會繼承已經配置的 `security_patch`；其他已配置的和未知的值都原樣留著。熱重載不做遷移，想把舊檔案升級就得重啟 keymint。未來那種不認識的版本，絕不會被覆寫。

### `[main]`

#### `backend`

就寫 `"injector"`。這是唯一支援的選擇，沒有別的執行時後端，別改。

#### `log_level`

決定 keymint 往外打什麼日誌。可選 `"off"`、`"error"`、`"warn"`、`"info"`、`"debug"`、`"trace"`。預設 `"debug"`，提 bug 回報時也用它最合適。`"trace"` 話更多，`"off"` 直接把正常日誌全關掉。

改這個要重啟 keymint。認不出的值會退回 `debug`，但別指望它，容易把拼字錯誤蓋過去。

#### `force_skip_system_biometric_hat_verification`

一個不安全的相容開關，專門給那些系統 KeyMint 驗不好生物識別權杖的裝置用。開成 `true`，KOBING 就不要求系統 KeyMint 校驗認證碼了，權杖結構沒問題就認。

除非維護者確認是某個裝置特有的毛病，否則一直保持 `false`。它不負責藏 root，也不是指紋、鎖屏出問題的萬靈丹。存成有效值後對新檢查立刻生效，不用重啟 keymint。

### `[crypto]`

這一節每個值都是機密。每個值剛好 32 位元組，寫成 64 個十六進位字元（`0-9`、`a-f`）。新建設定時 KOBING 會自己生成。

四個種子和隨機數欄位，要一直留著、別改動，跟著 KOBING 的資料一起私下備份好。改了或刪了任何一個，都得重啟 keymint，而且很可能導致既有的密鑰、或者綁定了認證的操作直接不能用。別拿別的裝置上的值，也別拿本文件裡的佔位符來頂替。

`shared_secret_seed` 或 `shared_secret_nonce` 如果缺了，KOBING 讀檔案時會重新隨機生成一批。那就不算穩定的生效設定，所以這兩個值務必都在。

#### `root_kek_seed`

用來派生保護 KOBING 密鑰 blob 的密鑰材料。它一變，那些用舊值建立的密鑰 KOBING 可能就打不開了。必須有，而且不能變。

#### `kak_seed`

KOBING 密鑰協商保護用的種子，跟 `root_kek_seed` 屬於同一套裝置機密。必須有，不能變。

#### `shared_secret_seed`

認證權杖校驗所用共享機密的種子部分。要跟 `shared_secret_nonce` 成對保留——只改一半，最終的機密照樣變。

#### `shared_secret_nonce`

共享機密的隨機數部分。同樣是完整的 64 字元十六進位值，不是什麼短計數器，也不用你手動重算。

#### `auth_token_hmac_key`

可選的顯式認證權杖 HMAC 密鑰。不寫這個欄位時，KOBING 會用 `shared_secret_seed` 加 `shared_secret_nonce` 自己推出來。一般使用者直接別寫這行。真要顯式給，也得剛好 64 個十六進位字元，同樣得保密、不能變。

### `[trust]`

這一節管的是密鑰證明裡上報出去的那些值。它不會修硬體、不會續憑證、不會解除 keybox 吊銷，也不負責藏 root。

#### `os_version`

寫 `"auto"` 就每次 keymint 行程啟動時自己偵測目前 Android 主版本；也可以寫 `0` 到 `99` 的整數釘死一個，例如 `12`、`16`、`17`。別在這裡寫帶點的版本號、SDK 號或者安全補丁日期。KeyMint 按 AOSP 的 `MMmmss` 公式編碼解析出的主版本，所以釘住的 `16` 上報出去是 `160000`。改這個要重啟 keymint。

#### `security_patch`

管的是 `ro.build.version.security_patch`。取值：

- `"auto"`：沿用目前的 `ro.build.version.security_patch`，不改寫；
- `"latest"`：解析時取目前日曆月的 5 號；
- 具體日期，寫成 `"YYYY-MM-DD"`，要帶前導零。

`"auto"` 的取值順序是：先用執行時屬性裡非空的值，再找標準 `build.prop` 位置裡的精確鍵，兩個都沒有才用 `2025-06-05`。執行時裡已經有的值會原樣用，不會被 `build.prop` 的值頂替。`"latest"` 和精確日期是刻意覆寫執行時屬性的，但 KOBING 從不會建立或刪掉它。`"auto"` 從不寫這個屬性。同一次啟動裡，先顯式覆寫或用了 `"latest"`，再切回 `"auto"`，會保留目前執行時值；想要系統原本的值只能重啟。

#### `os_patchlevel`

管 KeyMint 的 OS 補丁級別。`"auto"` 跟著生效的 `security_patch` 走；`"latest"` 和精確的 `"YYYY-MM-DD"` 會單獨給 KeyMint 覆寫，不寫別的屬性。最終值走 AOSP 的 `YYYY-MM-DD` 解析器，編碼成 `YYYYMM`。

#### `vendor_patchlevel`

管 KeyMint 的供應商補丁級別。`"auto"` 先讀執行時非空的 `ro.vendor.build.security_patch`，再找標準 `build.prop` 裡的精確鍵，都沒有就退回生效的 `os_patchlevel`。`"latest"` 和精確日期同樣可以用。最終值走 AOSP 的 `YYYY-MM-DD` 解析器，編碼成 `YYYYMMDD`。來源裡如果已經有非空值，不會因為後面解析失敗就被優先級更低的東西頂掉。KOBING 不寫供應商屬性。

#### `boot_patchlevel`

管 KeyMint 的啟動補丁級別。`"auto"` 先從生效的頂層 vbmeta 映像檔讀 `com.android.build.boot.security_patch`。這個屬性要是沒有，KOBING 會去生效啟動映像檔裡獨立的 vbmeta、或者 AVB 頁尾內嵌的 vbmeta 裡找同一個屬性，再不行才看啟動標頭。舊式標頭欄位只存年月、沒有日，所以線上值末尾是 `00`；全零欄位因此會變成 `20000000`——但這只有在前兩個 vbmeta 位置都沒給出該屬性時才會發生。啟動中繼資料解析失敗的話，回退順序是：執行時非空的 `ro.vendor.boot_security_patch` → 標準 `build.prop` 裡的精確鍵 → 生效的 `os_patchlevel`。

`"latest"`、精確的 `"YYYY-MM-DD"`，還有十進位 `u32` 線上值也都收。十進位能保留像 `"20000000"` 這種引導載入程式線上值，不把它當日期解釋。這幾種顯式寫法都不會去讀啟動中繼資料。啟動補丁級別解析既不看系統 TEE，也不寫啟動屬性。熱重載時，沒動過的 `"auto"` 會保住 keymint 降權之前解析到的那份值；從覆寫切回 `"auto"` 則要等 keymint 重啟才生效。顯式日期編碼成 `YYYYMMDD`。選出來的值轉不了的話，啟動會失敗；熱更新失敗就繼續用先前的執行時設定。

這四個補丁級別欄位，在同一次儲存裡沒有別的 `[trust]` 欄位一起變時，會在 keymint 執行期間一起解析、一起套用。現有 TA 就地更新，正在進行的操作和每次啟動的計數器都不受影響；表示形式上沒有實質變化的不會觸發更新。要是日誌說即時更新失敗，就重啟 keymint。

#### `vb_key`

管 32 位元組的驗證啟動公鑰摘要：

- `"auto"`：先讀 `ro.boot.vbmeta.public_key_digest`，讀不到就試著算頂層 vbmeta 的密鑰摘要，兩個都不行才用隨機值兜底；
- `"random"`：每次 keymint 啟動都生成新的；
- 64 字元十六進位串：釘死某個確切值。

除非你清楚自己在配什麼證明，不然保持 `"auto"`。改這個要重啟 keymint。要是 `"random"` 正開著、你想切回 `"auto"`，得整機重啟，讓 Android 先把原始啟動屬性恢復出來，`"auto"` 才讀得到。

#### `vb_hash`

管 32 位元組的驗證啟動雜湊：

- `"auto"`：先讀 `ro.boot.vbmeta.digest`，讀不到就試原始系統證明雜湊，兩個都不行才用隨機值兜底；
- `"random"`：每次 keymint 啟動都生成新的；
- 64 字元十六進位串：釘死某個確切值。

重啟規則跟 `vb_key` 一樣：正常改完重啟 keymint，從 `"random"` 回 `"auto"` 要整機重啟。

#### `verified_boot_state`

`true` 表示上報「已驗證啟動」，`false` 表示「未驗證」。跟 `device_locked` 各管各的。改它要重啟 keymint。

#### `device_locked`

`true` 表示上報裝置已鎖定，`false` 表示未鎖定。它並不會真的去鎖/解鎖引導載入程式。改它要重啟 keymint。

### `[device]`

應用明確要證明 ID 時，這一節提供裝置身份字串。這些都是個人資料。用裝置上已經生成好的值；改完這一節要重啟 keymint，好把一次性的證明 ID 快照重建一遍。

#### `brand`

證明 ID 請求裡上報的品牌，新建設定時一般取自 `ro.product.brand`。

#### `device`

證明 ID 請求裡上報的裝置代號，一般取自 `ro.product.device`。

#### `product`

證明 ID 請求裡上報的產品名，一般取自 `ro.product.name`。

#### `manufacturer`

證明 ID 請求裡上報的製造商，一般取自 `ro.product.manufacturer`。

#### `model`

證明 ID 請求裡上報的型號，一般取自 `ro.product.model`。

#### `serial`

證明 ID 請求裡上報的序號，一般取自 `ro.serialno`。當私密資訊對待，發報告前記得打碼。

#### `overrideTelephonyProperties`

建議值 `false`。這時 KOBING 會嘗試從裝置的電話服務和屬性回退裡，把空著的 `imei`、`imei2`、`meid` 填上。已經配好的非空值會被保留；每成功找到一個值，KOBING 還會試著寫回生效的 `config.toml`。

設成 `true`，KOBING 就跳過電話探索，這三個欄位完全照你寫的來（包括空字串）。只有你確實想釘死這幾個值時才用它。

#### `imei`

主 IMEI。裝置沒有 IMEI，或者本來就該自動填的，就留空。別為了讓某個應用滿意硬編一個。

#### `imei2`

第二個 IMEI。單卡裝置、還有一些雙卡裝置，留空很正常。它空著不影響 `imei`，也不影響其他非電話欄位。

#### `meid`

有 MEID 的裝置才用。很多裝置本來就沒有 MEID，空著沒問題。它空著不會讓可用的 IMEI 失效。

### `config.toml` 應用匯總

| 欄位 | 要做什麼 |
| --- | --- |
| `[main].log_level` | 重啟 keymint。 |
| `[main].force_skip_system_biometric_hat_verification` | 有效儲存後對新檢查生效。 |
| 所有 `[crypto]` 欄位 | 重啟 keymint；改值可能讓密鑰不能用。 |
| `[trust].security_patch`、`os_patchlevel`、`vendor_patchlevel`、`boot_patchlevel` | 沒有別的 `[trust]` 欄位一起變時，作為一組熱套用；否則重啟 keymint。 |
| `[trust].os_version` | 重啟 keymint。 |
| 其他 `[trust]` 欄位 | 重啟 keymint。 |
| 所有 `[device]` 欄位 | 重啟 keymint，重建快取的 ID 快照。 |
| `vb_key` 或 `vb_hash` 從 `"random"` 改回 `"auto"` | 整機重啟。 |

## `injector.toml`

### 完整帶註釋示例

```toml
# 設定格式，固定為 1。
version = 1

# 包名名單不在這了。它挪到了 bm.txt，路徑、格式和規則見下面
# bm.txt 那一節。

[main]
# 路由總開關。正常用保持 true。
enabled = true
# Injector 日誌級別：off、error、warn、info、debug、trace。
log_level = "debug"

[filter]
# 是否執行 bm.txt 名單和下面的安全規則。
enabled = true
# 就算某個共享包被允許了，這些包也絕不用 KOBING。
deny_packages = []
# 攔掉核心 Android 和系統身份。保持 true。
block_android_package = true
# 包名解析不出來的呼叫方，是否拒絕。保持 false。
allow_unknown_package = false

[intercept]
# 被允許的呼叫方，它的每個具名 KeyStore 操作是否轉到 KOBING。
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

### 頂層字段

#### `version`

injector 的設定格式版本，保持整數 `1`。跟 Android 版本、KOBING 版本號無關。熱重載會拒絕別的值，繼續用最後一份有效執行時設定。

injector 啟動時缺 `version` 就按 `0` 算，`0` 會就地升到 `1`，檔案其餘部分不動。熱重載不做這個升級，所以要升這種檔案得重啟 injector。未來不認識的版本絕不會被覆寫。

文件裡寫到的欄位如果沒寫，用預設值。頂層和具名節裡那些沒記錄的未知欄位會被拒，所以別加本文件沒講的欄位名。

#### 包名允許清單

`injector.toml` 不再存包名名單了。能用的精確包名單獨放在 `bm.txt`。路徑、格式和規則見下面 `bm.txt` 一節。

### `[main]`

#### `enabled`

injector 的總路由開關。`true` 時，每個新請求交給過濾器和 `[intercept]` 決定。`false` 就不再往 KOBING 路由，普通請求照舊走系統。正常用 KOBING 就保持 `true`。

應用還開著密鑰操作的時候，別去動這個開關。儲存改動、重啟 injector，要切路由就把應用重新打開。

#### `log_level`

管 injector 的日誌。可選 `"off"`、`"error"`、`"warn"`、`"warning"`、`"info"`、`"debug"`、`"trace"`，其中 `"warning"` 是 `"warn"` 的別名。比對不分大小寫，不過建議寫小寫。預設 `"debug"`，提 bug 回報一般也用它。

有效改動不用重啟 injector 就能換級別。認不出的字串不會讓 TOML 檔案失效，injector 會退回 `debug`。

### `[filter]`

過濾器開著時，KOBING 按這個順序判斷呼叫方：

1. `block_android_package = true` 時，先拒掉核心 Android 或系統身份。
2. 包名解析不出來的，看 `allow_unknown_package`。
3. 解析出的包裡有任何一個在 `deny_packages` 裡，整個身份都拒。
4. 解析出的包一個都不在 `bm.txt` 裡，拒掉。
5. 以上都沒問題，就放它走已啟用的 `[intercept]` 路由。

幾個包共享同一個 Android 身份時，順序就很關鍵：拒絕規則優先於 `bm.txt` 裡的比對。

常規過濾判斷之後，還有 `bm.txt` 一節講的那個窄範圍授權例外，能給某個未知或範圍外的應用留條存取權限。它不會推翻 Android 包攔截或 `deny_packages`。

#### `enabled`

`true` 會真正執行 `bm.txt` 名單、拒絕名單、Android 包攔截和未知包策略。`false` 就跳過這四項檢查，任何呼叫方都能存取 `[intercept]` 裡開著的操作。

關掉過濾器可能把 Android 服務、還有一堆無關應用都路由到 KOBING，進而搞壞解鎖、應用儲存或者介面。保持 `true`。

#### `deny_packages`

一個精確包名陣列，裡面的包不許用 KOBING。某個包被選中、又跟另一個必須留在系統的包共享 Android 身份時，這個就有用。該身份解析出的包只要有一個被拒，整個身份都拒，哪怕另一個包已經寫在 `bm.txt` 裡。

預設是空陣列 `[]`。列表用帶引號、逗號分隔的 TOML 語法，跟單獨的 `bm.txt` 名單互不相干。

#### `block_android_package`

`true` 時，還沒輪到看 `bm.txt` 就把核心 Android 和系統身份拒了；解析出的包名等於 `android`、或者以 `android.` 開頭的呼叫方也會被拒。注意，這不代表名字以 `com.android.` 開頭的普通應用會被一併攔掉。

保持 `true`。設成 `false` 只是把這道安全檢查拿掉了，其餘過濾規則照舊。

#### `allow_unknown_package`

管的是 Android 包名解析不出來的呼叫方。`false` 直接拒，這是穩妥的預設值。`true` 就允許身份不明、又沒在 `bm.txt` 裡比對上的應用；不過 `block_android_package = true` 時，核心 Android 身份還是會被拒。

它不是「通吃所有應用」的開關。除非維護者確認某個支援的應用死活解析不出來，否則保持 `false`。

### `[intercept]`

每個開關對應一個 Android KeyStore 服務操作。對過濾器放行的呼叫方，`true` 就把該操作轉到 KOBING，`false` 就留在系統裡。這些開關不會遷移既有密鑰，也不會讓系統建立的密鑰引用變成 KOBING 能用。

KOBING 那個授權例外跟普通包路由是兩碼事。請求帶著已確認的 KOBING 授權，就算接收應用不在 `bm.txt` 名單裡，照樣能回到 KOBING，被授權的密鑰就還能用。

正常用就全部保持 `true`。同一個應用混著走系統和 KOBING，容易出現密鑰找不到、列表對不上或者後續操作失敗。

#### `get_security_level`

管對 TEE 或 StrongBox 安全級別代號的請求。應用拿到這個代號，後面才有建立、匯入、使用密鑰這些操作。

#### `get_key_entry`

管取回既有密鑰條目，包括它的中繼資料和後續操作用的代號。

#### `update_subcomponent`

管替換既有密鑰條目的憑證或憑證鏈組件。

#### `list_entries`

管列出所請求命名空間裡的密鑰別名。

#### `delete_key`

管刪除具名密鑰。選中的後端說了算；KOBING 不會順手刪掉對應的系統密鑰來頂替。

#### `grant`

管把某個密鑰的存取權限授予另一個應用。

#### `ungrant`

管撤銷之前授予的密鑰權限。

#### `get_number_of_entries`

管統計命名空間裡的密鑰條目數。

#### `list_entries_batched`

管密鑰條目的分頁或批次列出。

#### `get_supplementary_attestation_info`

管取回受支援證明請求要用的補充資訊。

### 按包劃分的子表

`[scoop.com.example.app]` 這類按包劃分的表，還有 `mode = "strict"` 這類值，都不是支援的路由選項。檔案解析時它們可能被留著，但不會改變哪個後端處理請求。別加它們：名單用 `bm.txt`，路由用 `[filter]` 和 `[intercept]`。

### `injector.toml` 應用匯總

每個已記錄欄位的有效改動都會對新請求生效，不用重啟裝置。改的是 `bm.txt` 名單、`[main].enabled`、`[filter]` 或 `[intercept]`，想要路由變化後有個乾淨邊界，就重啟 injector 並把受影響的應用重新打開。語法錯誤、未知欄位，或者未來不支援的 `version`，會讓最後一份有效執行時設定繼續生效；如果這些在 injector 啟動時就存在，KOBING 路由會一直關著，直到檔案修好。

## `bm.txt`

`bm.txt` 裡是可以使用 KOBING 的精確 Android 包名。它取代了原先放在 `injector.toml` 裡的 `scoop` 陣列。

### 路徑

- 執行時實體：`/data/surprise/bm.txt`

injector 直接讀這個實體路徑。

### 格式

- 一行一個包名，例如 `com.example.app`。
- 空行、以及第一個非空字元是 `#` 的行，忽略。
- 首尾空格去掉，重複的合併成一條。
- 不支援應用標籤、部分名稱或萬用字元。

模組安裝時、以及每次啟動時，檔案不在的話，模組會用打包的預設列表生成 `bm.txt`，然後把擁有者改成 `keystore`、權限改成 `0644`。改這個檔案對新請求立即生效，不用重啟；想要清晰的路由邊界，就重啟 injector 並重新打開受影響的應用。

### 預設內容

```text
io.github.vvb2060.keyattestation
com.google.android.gsf
com.google.android.gms
com.android.vending
com.eltavine.duckdetector
```

Android 允許幾個包共用一個身份。這種情況下列出任一包就放行整個身份，除非某條過濾規則拒了這組裡的某個包。增刪某個包，並不會在系統和 KOBING 之間搬密鑰或轉密鑰；應用可能因此打不開之前用另一條路由建立的密鑰。

還有一個窄範圍的已授權密鑰例外。不在 `bm.txt` 裡的應用、或者包名解析不出來的應用，仍然可以用 KOBING 去確認某個 KOBING 密鑰的存取授權。這樣別的應用主動共享出來的密鑰還能繼續用，同時又不會把 KOBING 的通用存取權給接收方。被 Android 攔掉的、以及被拒絕名單點名的呼叫方，拿不到這個例外。
