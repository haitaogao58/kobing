# 配置指南

[English](CONFIGURATION.md) | [简体中文](CONFIGURATION.zh-CN.md) | **繁體中文**

KoBing（KOBING）使用三個生效的配置文件：

- `/data/surprise/waste/config.toml` 控制 KeyMint 服務、其上報的身份，以及用於 KOBING 創建的密鑰的機密。
- `/data/surprise/injector.toml` 選擇哪些 KeyStore 請求被路由到 KOBING。
- `/data/surprise/bm.txt` 列出可以使用 KOBING 的應用包。

本指南描述當前構建所使用的生效配置。示例之後附有獨立的逐字段參考，因此示例中的簡短註釋並非唯一的說明。

**跳轉：** [`config.toml`](#configtoml) | [`injector.toml`](#injectortoml) | [`bm.txt`](#bmtxt)

## 編輯之前

對於一般使用，通常唯一需要修改的設置是 `bm.txt` 中的包名允許清單。請保持 `injector.toml`、安全過濾器、所有 `[intercept]` 開關以及生成的 `[crypto]` 值不變。

在進行修改之前：

1. 對所有生效文件做一份私有備份。
2. 編輯 `/data/surprise/`（以及 `/data/surprise/waste/`）下的文件，而不是模組 ZIP 中的副本。
3. 保持字符串在引號內，布爾值使用 `true` 或 `false`，並將包名放入 `bm.txt`，每行一個精確的包名。
4. 每次只改動一處，保存完整文件，並在改動後檢查對應的日誌。

切勿公開 `[crypto]` 值、IMEI、IMEI2、MEID、序列號，或任一配置文件的未脫敏副本。

## 改動如何被加載

兩個組件都會監視其生效文件以獲得有效改動。它們的行為並不完全相同：

- 有效的 `injector.toml` 或 `bm.txt` 會應用到新請求，無需重啟。
- 有效的 `config.toml` 會被自動讀取，但只有四個補丁級別字段和生物識別兼容開關能夠在不重啟 keymint 的情況下完全生效。下方的字段參考會說明何時需要重啟。
- 在組件運行期間保存的格式錯誤的文件會被拒絕，內存中最後一個有效配置保持生效。
- 若 keymint 啟動時存在格式錯誤的 `config.toml`，會阻止 keymint 啟動。修正該文件並重啟 keymint。
- 若 injector 啟動時存在格式錯誤的 `injector.toml`，KOBING 請求路由將保持禁用。保存一個有效文件可讓監視器自動恢復路由；僅當無法恢復時才重啟 injector。
- 若組件啟動時任一文件缺失，KOBING 會創建一個帶有生成默認值的新文件。這並不是重置可用配置的安全方式：重新生成的機密無法恢復由先前機密保護的密鑰。

重啟命令記錄在[重啟 keymint 與 injector](../README.zh-TW.md#重啟-keymint-與-injector)中。在更改應用路由後，請關閉並重新打開受影響的應用，以避免將已打開的操作與新路由混用。若需要進程重啟來獲得清晰的邊界，只需重啟 injector。僅針對 injector 的設置更改不需要重啟 keymint。

## `config.toml`

### 完整帶註釋示例

下方 `[crypto]` 下的數值是刻意不可用的脫敏佔位符。真實的生效文件包含唯一的、生成的十六進制值。切勿將這些佔位符值粘貼到設備中，也切勿替換可用文件中已存在的值。`[trust]` 與 `[device]` 的數值同樣是示例；除非你打算更改上報的身份，否則請保留生效文件中的值。

```toml
# 配置格式。保持為 2。
version = 2

[main]
# 受支持的服務連接。保持此值不變。
backend = "injector"
# KeyMint 日誌詳細程度：off、error、warn、info、debug 或 trace。
log_level = "debug"
# 不安全的生物識別兼容開關。常規使用請保持 false。
force_skip_system_biometric_hat_verification = false

[crypto]
# 僅脫敏佔位符。請保留生成的 64 字符值。
root_kek_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
kak_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_seed = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
shared_secret_nonce = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# 可選的專家覆蓋。通常讓此行缺失。
# auth_token_hmac_key = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"

[trust]
# 每次 keymint 啟動時檢測 Android 主版本；使用整數可固定它。
os_version = "auto"
# 使用 auto、latest 或精確的 YYYY-MM-DD 日期；boot 也接受十進制 u32。
security_patch = "auto"
os_patchlevel = "auto"
vendor_patchlevel = "auto"
boot_patchlevel = "auto"
# 使用 auto、random 或恰好 64 個十六進制字符。
vb_key = "auto"
vb_hash = "auto"
# 為 true 時上報驗證啟動和已鎖定引導加載程序。
verified_boot_state = true
device_locked = true

[device]
# 當應用請求證明 ID 時上報的設備身份字符串。
brand = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
device = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
product = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
manufacturer = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
model = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
serial = "KEEP_THE_VALUE_FROM_THE_ACTIVE_FILE"
# false 時僅在可用時從設備填充空的電話相關字段。
overrideTelephonyProperties = false
# 空的可選標識符是有效的；不要臆造缺失的值。
meid = ""
imei = ""
imei2 = ""
```

### 頂層字段

#### `version`

標識配置格式。支持的值為整數 `2`。它既不是 Android 版本，也不是 KOBING 發行號。不要遞增它；當前文件應保持該值不變。熱重載會拒絕其他值，並保留最後一個有效的運行時配置。

在 keymint 啟動時，缺失的 `version` 會被視為 `0`。版本 `0` 和 `1` 會在服務啟動前就地遷移為 `2`，並將 `os_version` 設為 `"auto"`，以便後續 Android 升級在下一次 keymint 啟動時被檢測到。啟動還會移除過時的 `trust_record`。對於版本 `0`，缺失的補丁級別字段會繼承已配置的 `security_patch`。其他已配置及未知的值會被保留。熱重載期間不會執行遷移，因此請重啟 keymint 以遷移較舊的文件。不受支持的未來版本絕不會被覆蓋。

### `[main]`

#### `backend`

使用 `"injector"`。這是唯一受支持的用戶選擇，沒有其他可選的運行時後端，因此該字段應保持不變。

#### `log_level`

控制 keymint 寫入的消息。使用 `"off"`、`"error"`、`"warn"`、`"info"`、`"debug"` 或 `"trace"` 之一。`"debug"` 是默認值，也是提交錯誤報告時最有用的級別。`"trace"` 更為冗長；`"off"` 會抑制正常日誌輸出。

更改此字段需要重啟 keymint。無法識別的值會回退到 `debug`，但依賴該回退可能會掩蓋拼寫錯誤。

#### `force_skip_system_biometric_hat_verification`

這是一個不安全的兼容開關，適用於系統 KeyMint 無法正確驗證生物識別認證令牌的設備。當為 `true` 時，KOBING 會在不要求系統 KeyMint 驗證其認證碼的情況下，接受結構有效的令牌。

除非維護者在診斷已確認的設備特定問題，否則請保持 `false`。它並不隱藏 root，也不是指紋或鎖屏故障的通用修復手段。有效保存後會應用到新的檢查，無需重啟 keymint。

### `[crypto]`

本節的每個值都是私密的。每個值恰好為 32 字節，以 64 個十六進制字符（使用 `0-9` 和 `a-f`）表示。KOBING 在創建新配置時會生成這些值。

請保持四個生成的種子與隨機數字段都存在且穩定，並將其與 KOBING 數據一起私下備份。更改或移除其中任何一個都需要重啟 keymint，並可能導致現有密鑰或綁定認證的操作不可用。來自其他設備的值以及本指南中的脫敏佔位符不能替代生效值。

如果缺少 `shared_secret_seed` 或 `shared_secret_nonce`，KOBING 在讀取文件時會生成新的隨機替代值。這並非穩定的生效配置，因此請確保兩個生成值都保持存在。

#### `root_kek_seed`

該種子用於派生保護 KOBING 密鑰 blob 的密鑰材料。如果它變化，KOBING 可能無法再打開使用先前值創建的密鑰。它必須存在且必須保持不變。

#### `kak_seed`

該種子用於 KOBING 的密鑰協商保護。它屬於與 `root_kek_seed` 相同的設備特定機密集合。它必須存在且必須保持不變。

#### `shared_secret_seed`

這是用於認證令牌驗證的共享機密參數的種子部分。請將其與 `shared_secret_nonce` 一起保留；僅更改其中一半仍會改變最終的機密。

#### `shared_secret_nonce`

這是共享機密參數的隨機數部分。它同樣是完整的 64 字符十六進制值，不是短計數器，也不是需要手動重新生成的值。

#### `auth_token_hmac_key`

這個可選字段提供顯式的認證令牌 HMAC 密鑰。當它缺失時，KOBING 通過 `shared_secret_seed` 與 `shared_secret_nonce` 派生所需的密鑰。普通用戶應讓該字段缺失。如果顯式提供，它也必須恰好包含 64 個十六進制字符，並且必須保持私密和穩定。

### `[trust]`

這些字段控制通過密鑰證明上報的值。它們不會修復硬件、續期證書、移除 keybox 吊銷，也不會隱藏 root。

#### `os_version`

使用 `"auto"` 在每次 keymint 進程啟動時檢測當前 Android 主版本，或使用 `0` 到 `99` 的整數來固定一個主版本，例如 `12`、`16` 或 `17`。不要在此寫入帶點的版本號、SDK 號或安全補丁日期。KeyMint 使用 AOSP 的 `MMmmss` 公式對解析出的主版本進行編碼，因此固定的 `16` 會上報為 `160000`。更改此字段需要重啟 keymint。

#### `security_patch`

控制 `ro.build.version.security_patch`。它接受：

- `"auto"`：使用當前的 `ro.build.version.security_patch` 值而不寫入它；
- `"latest"`：在解析該值時使用當前日曆月的第五天；或
- 實際日期，寫作 `"YYYY-MM-DD"`，包括前導零。

`"auto"` 首先使用非空的運行時屬性，其次是來自標準 `build.prop` 位置的精確鍵，最後若兩個來源都不可用則使用 `2025-06-05`。存在的運行時值會按原樣使用，而不會被 `build.prop` 的值替換。`"latest"` 和精確日期會有意覆蓋現有的運行時屬性，但 KOBING 從不創建或刪除它。`"auto"` 從不寫入該屬性。在一次顯式或 `"latest"` 覆蓋後，同一次啟動中切換回 `"auto"` 會保留當前的運行時值；重啟以恢復系統提供的值。

#### `os_patchlevel`

控制 KeyMint OS 補丁級別。`"auto"` 跟隨生效的 `security_patch`；`"latest"` 和精確的 `"YYYY-MM-DD"` 日期會為 KeyMint 覆蓋它，而不寫入另一屬性。最終值使用 AOSP 的 `YYYY-MM-DD` 解析器解析，並編碼為 `YYYYMM`。

#### `vendor_patchlevel`

控制 KeyMint 供應商補丁級別。`"auto"` 首先讀取非空的運行時 `ro.vendor.build.security_patch`，其次是來自標準 `build.prop` 位置的精確鍵，最後回退到生效的 `os_patchlevel`。`"latest"` 和精確的 `"YYYY-MM-DD"` 日期同樣被接受。最終值使用 AOSP 的 `YYYY-MM-DD` 解析器解析，並編碼為 `YYYYMMDD`。存在的非空來源不會僅因後續解析失敗就被低優先級來源替換。KOBING 不寫入供應商屬性。

#### `boot_patchlevel`

控制 KeyMint 啟動補丁級別。`"auto"` 首先從生效的頂層 vbmeta 鏡像讀取 `com.android.build.boot.security_patch`。如果該屬性缺失，KOBING 會從生效啟動鏡像的獨立 vbmeta 或 AVB 頁腳內嵌 vbmeta 中讀取同一屬性，然後回退到啟動頭。舊式頭字段存儲年和月但不含日，因此其線上值以 `00` 結尾；全零字段因此變為 `20000000`，但僅在兩個 vbmeta 位置均未提供該屬性之後。如果啟動元數據解析失敗，KOBING 使用以下回退順序：非空的運行時 `ro.vendor.boot_security_patch`、來自標準 `build.prop` 位置的精確鍵，然後是生效的 `os_patchlevel`。

`"latest"`、精確的 `"YYYY-MM-DD"` 日期以及十進制 `u32` 線上值同樣被接受。十進制形式會保留諸如 `"20000000"` 的引導加載程序線上值，而不將其解釋為日期。這些顯式模式不會讀取啟動元數據。啟動補丁級別解析不會讀取系統 TEE 或寫入啟動屬性。在熱重載期間，未更改的 `"auto"` 會保留在 keymint 降權之前解析出的值；從覆蓋切回 `"auto"` 會在 keymint 重啟後生效。顯式日期編碼為 `YYYYMMDD`。如果選定的值無法轉換，啟動會失敗；失敗的熱更新會保留先前的運行時配置。

當同一次保存中沒有其他 `[trust]` 字段變化時，這四個補丁級別字段會在 keymint 運行期間一起解析並應用。現有 TA 會就地更新，以便進行中的操作和每次啟動的計數器保持完好；等效的啟動表示不會觸發更新。如果對應的日誌報告實時更新失敗，請重啟 keymint。

#### `vb_key`

控制 32 字節的驗證啟動公鑰摘要：

- `"auto"` 首先讀取 `ro.boot.vbmeta.public_key_digest`，然後嘗試計算頂層 vbmeta 密鑰摘要，僅當兩個來源都不可用時才使用隨機回退；
- `"random"` 在每次 keymint 啟動時生成新值；或
- 64 字符的十六進制字符串固定一個精確值。

除非你了解所配置的證明配置，否則請保持 `"auto"`。更改此字段需要重啟 keymint。如果 `"random"` 處於活動狀態而你又將其改回 `"auto"`，請重啟整個設備，以便 Android 在 `"auto"` 讀取之前恢復原始啟動屬性。

#### `vb_hash`

控制 32 字節的驗證啟動哈希：

- `"auto"` 首先讀取 `ro.boot.vbmeta.digest`，然後嘗試原始系統證明哈希，僅當兩個來源都不可用時才使用隨機回退；
- `"random"` 在每次 keymint 啟動時生成新值；或
- 64 字符的十六進制字符串固定一個精確值。

應用與 `vb_key` 相同的重啟規則：正常更改後重啟 keymint，從 `"random"` 返回 `"auto"` 時重啟整個設備。

#### `verified_boot_state`

`true` 將驗證啟動狀態上報為已驗證；`false` 上報為未驗證。這與 `device_locked` 開關相互獨立。更改它需要重啟 keymint。

#### `device_locked`

`true` 上報設備啟動狀態為已鎖定；`false` 上報為未鎖定。這並不會真正鎖定或解鎖引導加載程序。更改它需要重啟 keymint。

### `[device]`

當應用顯式請求證明 ID 時，本節提供設備身份字符串。這些值是個人數據。使用已為設備生成的值，並在更改本節後重啟 keymint，以便重建一次性的證明 ID 快照。

#### `brand`

在證明 ID 請求中上報的產品品牌，創建新配置時通常基於 `ro.product.brand`。

#### `device`

在證明 ID 請求中上報的設備代號，通常基於 `ro.product.device`。

#### `product`

在證明 ID 請求中上報的產品名稱，通常基於 `ro.product.name`。

#### `manufacturer`

在證明 ID 請求中上報的製造商名稱，通常基於 `ro.product.manufacturer`。

#### `model`

在證明 ID 請求中上報的型號名稱，通常基於 `ro.product.model`。

#### `serial`

在證明 ID 請求中上報的設備序列號，通常基於 `ro.serialno`。請將其視為私密信息，並在報告中脫敏。

#### `overrideTelephonyProperties`

在推薦值 `false` 下，KOBING 會嘗試僅從設備的電話服務及屬性回退中填充為空的 `imei`、`imei2` 和 `meid` 字段。已配置的非空值會被保留，並且 KOBING 會嘗試將每個成功發現的值寫回生效的 `config.toml`。

在 `true` 下，KOBING 會跳過電話發現，並完全按所寫內容使用這三個已配置字段，包括空字符串。僅當你有意固定這些值時才使用它。

#### `imei`

主 IMEI。當設備沒有 IMEI 或應由自動發現填充時，請將其留空。不要為滿足某個應用而臆造值。

#### `imei2`

第二個 IMEI。單卡及部分雙卡設備可以合法地讓它為空。它的缺失不會使 `imei` 或非電話類設備字段失效。

#### `meid`

提供 MEID 的設備所使用的 MEID。許多設備沒有 MEID，因此空值有效。它的缺失不會使可用的 IMEI 失效。

### `config.toml` 應用匯總

| 字段 | 所需操作 |
| --- | --- |
| `[main].log_level` | 重啟 keymint。 |
| `[main].force_skip_system_biometric_hat_verification` | 有效保存後應用到新的檢查。 |
| 所有 `[crypto]` 字段 | 重啟 keymint；更改值可能導致密鑰不可用。 |
| `[trust].security_patch`、`os_patchlevel`、`vendor_patchlevel`、`boot_patchlevel` | 當沒有其他 `[trust]` 字段變化時作為一組熱應用；否則重啟 keymint。 |
| `[trust].os_version` | 重啟 keymint。 |
| 其他 `[trust]` 字段 | 重啟 keymint。 |
| 所有 `[device]` 字段 | 重啟 keymint 以重建緩存的 ID 快照。 |
| `vb_key` 或 `vb_hash` 從 `"random"` 到 `"auto"` | 重啟整個設備。 |

## `injector.toml`

### 完整帶註釋示例

```toml
# 配置格式。保持為 1。
version = 1

# 包名允許清單不再存儲於此。它位於 bm.txt；其路徑、格式與規則見下方
# bm.txt 一節。

[main]
# 請求路由的總開關。常規使用請保持 true。
enabled = true
# Injector 日誌詳細程度：off、error、warn、info、debug 或 trace。
log_level = "debug"

[filter]
# 強制執行 bm.txt 允許清單及下方安全規則。
enabled = true
# 即使另一個共享包被允許，也絕不使用 KOBING 的包。
deny_packages = []
# 阻止核心 Android 和系統身份。保持 true。
block_android_package = true
# 拒絕無法找到包名的調用方。保持 false。
allow_unknown_package = false

[intercept]
# 將被允許的調用方的每個具名 KeyStore 操作路由到 KOBING。
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

標識 injector 配置格式。保持整數值 `1`。它既不是 Android 版本，也不是 KOBING 發行號。熱重載會拒絕其他值，並保留最後一個有效的運行時配置。

在 injector 啟動時，缺失的 `version` 會被視為 `0`，版本 `0` 會就地遷移為 `1`，同時保留文件的其餘部分。版本 `0` 不會在熱重載期間遷移，因此請重啟 injector 以遷移此類文件。不受支持的未來版本絕不會被覆蓋。

如果省略了某個已記錄的 injector 字段，將使用其默認值。已記錄的頂層及具名節中的未知字段會被拒絕，因此不要添加本指南未描述的字段名。

#### 包名允許清單

`injector.toml` 不再存儲包名允許清單。可以使用 KOBING 的精確包名保存在一個單獨的文件 `bm.txt` 中。其路徑、格式與規則見下方 `bm.txt` 一節。

### `[main]`

#### `enabled`

這是 injector 的總路由開關。`true` 讓過濾器與 `[intercept]` 設置決定每個新請求。`false` 會停止新的 KOBING 路由，使普通請求繼續走系統。常規 KOBING 使用請保持 `true`。

避免在應用有密鑰操作打開時更改此開關。保存更改，重啟 injector，並在有意識切換路由時重新打開應用。

#### `log_level`

控制 injector 消息。接受的值有 `"off"`、`"error"`、`"warn"`、`"warning"`、`"info"`、`"debug"` 和 `"trace"`；`"warning"` 是 `"warn"` 的別名。匹配不區分大小寫，但推薦使用小寫值。`"debug"` 是默認值，也是提交錯誤報告時的常規選擇。

有效的文件更改會在不重啟 injector 的情況下更新級別。無法識別的字符串不會使 TOML 文件失效；injector 會改用 `debug`。

### `[filter]`

在過濾器啟用的情況下，KOBING 按以下順序評估調用方：

1. 當 `block_android_package = true` 時，拒絕核心 Android 或系統身份。
2. 如果其包名無法解析，則遵循 `allow_unknown_package`。
3. 如果任何解析出的包在 `deny_packages` 中，則拒絕整個身份。
4. 如果其解析出的包均未列在 `bm.txt` 中，則拒絕它。
5. 否則允許其使用已啟用的 `[intercept]` 路由。

對於共享同一 Android 身份的包，此順序很重要：拒絕規則優先於 `bm.txt` 中的匹配條目。

在此常規過濾決策之後，`bm.txt` 一節所述的、KOBING 所屬的窄範圍授權例外，可為未知或超出範圍的某個應用保留訪問權限。它不會覆蓋 Android 包阻止或 `deny_packages`。

#### `enabled`

`true` 強制執行 `bm.txt` 允許清單、拒絕清單、Android 包阻止以及未知包策略。`false` 會繞過全部四項檢查，並允許每個調用方訪問 `[intercept]` 下啟用的任何操作。

禁用過濾器可能將 Android 服務及無關應用路由到 KOBING，並可能破壞解鎖、應用存儲或用戶界面。請保持 `true`。

#### `deny_packages`

這是一個精確包名的數組，這些包不得使用 KOBING。當某個已選包與另一個必須留在系統的包共享其 Android 身份時，它很有用。如果為該身份解析出的任一包被拒絕，則整個身份都會被拒絕，即使另一個包已列在 `bm.txt` 中。

空數組 `[]` 是默認值。該列表使用帶引號、逗號分隔的 TOML 語法；它與單獨的 `bm.txt` 允許清單無關。

#### `block_android_package`

`true` 在考慮 `bm.txt` 之前就拒絕核心 Android 和系統身份。它還會拒絕解析出的包名等於 `android` 或以 `android.` 開頭的調用方。這並不意味著每個名稱以 `com.android.` 開頭的普通應用都會被自動阻止。

請保持此設置為 `true`。將其設為 `false` 只是移除了這項安全檢查；其餘過濾規則仍然適用。

#### `allow_unknown_package`

控制 Android 包名無法解析的調用方。`false` 拒絕該調用方，這是安全的默認值。`true` 允許未解析的應用身份而無需在 `bm.txt` 中匹配；當 `block_android_package = true` 時，核心 Android 身份仍會被拒絕。

此設置不是「所有應用」開關。除非維護者已確認某個受支持的應用無法正常解析，否則請保持 `false`。

### `[intercept]`

每個開關控制一個 Android KeyStore 服務操作。對於被過濾器允許的調用方，`true` 將該操作路由到 KOBING，`false` 將該操作留在系統上。這些開關不會遷移現有密鑰，也不會使系統創建的密鑰引用可被 KOBING 使用。

KOBING 所屬的授權例外與普通包路由相互獨立。帶有已確認 KOBING 授權的請求，即使接收應用在 `bm.txt` 允許清單之外，仍可返回 KOBING，從而使已授權的密鑰保持可用。

常規使用請保持所有開關為 `true`。對同一應用混用系統與 KOBING 操作可能導致密鑰缺失錯誤、列表不一致或後續操作失敗。

#### `get_security_level`

控制對 TEE 或 StrongBox KeyStore 安全級別句柄的請求。應用將該句柄用於後續操作，如創建、導入和使用密鑰。

#### `get_key_entry`

控制對現有密鑰條目的檢索，包括其元數據及用於後續密鑰操作的句柄。

#### `update_subcomponent`

控制替換現有密鑰條目的證書或證書鏈組件。

#### `list_entries`

控制列出所請求命名空間中的密鑰別名。

#### `delete_key`

控制刪除具名密鑰。選定的後端具有權威性；KOBING 不會刪除匹配的系統密鑰作為替代。

#### `grant`

控制授予另一個應用訪問某密鑰的權限。

#### `ungrant`

控制移除先前授予的密鑰權限。

#### `get_number_of_entries`

控制統計命名空間中的密鑰條目數。

#### `list_entries_batched`

控制密鑰條目的分頁或批量列出。

#### `get_supplementary_attestation_info`

控制檢索受支持的證明請求所使用的補充信息。

### 按包劃分的子表

諸如 `[scoop.com.example.app]` 的按包劃分的表，以及諸如 `mode = "strict"` 的值，都不是受支持的路由選項。它們在文件被解析時可能被保留，但不會改變由哪個後端處理請求。不要添加它們；允許清單請使用 `bm.txt`，路由請使用 `[filter]` 和 `[intercept]`。

### `injector.toml` 應用匯總

每個有效的已記錄字段更改都會應用到新請求，無需重啟設備。對於 `bm.txt` 允許清單、`[main].enabled`、`[filter]` 或 `[intercept]` 的更改，當你需要在路由變化後獲得清晰邊界時，請重啟 injector 並重新打開受影響的應用。語法錯誤、未知字段或不受支持的未來 `version` 會讓最後一個有效的運行時配置保持生效；如果它們在 injector 啟動時存在，則會使 KOBING 請求路由保持禁用，直到文件被修正。


## `bm.txt`

`bm.txt` 列出可以使用 KOBING 的精確 Android 包名。它取代了原先位於 `injector.toml` 內的 `scoop` 數組。

### 路徑

- 運行時實體：`/data/surprise/bm.txt`

injector 直接讀取該實體路徑。

### 格式

- 每行一個包名，例如 `com.example.app`。
- 空行以及第一個非空格字符為 `#` 的行會被忽略。
- 首尾空格會被去除，重複條目會合併為一條。
- 不接受應用標籤、部分名稱或通配符。

在模組安裝時以及每次啟動時，如果文件缺失，模組會從打包的默認列表生成 `bm.txt`，然後將所有權修正為 `keystore`、權限修正為 `0644`。編輯該文件會應用到新請求，無需重啟；當你需要清晰的路由邊界時，請重啟 injector 並重新打開受影響的應用。

### 默認內容

```text
io.github.vvb2060.keyattestation
com.google.android.gsf
com.google.android.gms
com.android.vending
com.eltavine.duckdetector
```

Android 可以為多個包分配同一身份。在這種情況下，只要列出其中任何一個包，就允許該共享身份，除非某條過濾規則拒絕了該組中的某個包。添加或移除某個包不會在系統與 KOBING 之間移動或轉換密鑰；應用可能失去對通過另一條路由創建的密鑰的訪問權限。

存在一個窄範圍的已授權密鑰例外。位於 `bm.txt` 之外的應用，或其包名無法解析的應用，仍可使用 KOBING 確認屬於某個 KOBING 密鑰的密鑰訪問授權。這樣可使由另一應用刻意共享的密鑰保持可用，而不授予接收應用通用的 KOBING 訪問權限。被 Android 阻止及被拒絕清單列出的調用方不會獲得此例外。