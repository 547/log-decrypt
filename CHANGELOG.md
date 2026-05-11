# Log Decrypt Skill 变更日志

## v2026-05-11
### 更新
- SKILL.md 简介：新增支持文件内容、直接密文两种输入方式

### 优化
- `decrypt_content_direct()`：解密成功后（JSON string decrypted），将 decrypted 从 string 转为 dict，供 `json_fmt` 正确格式化

### 重构
- 新增 `scripts/json_utils.py`：`json_parse`、`json_fmt`、`json_load` 统一管理所有 JSON 序列化/反序列化逻辑
- `AESCBCDecryptor.decrypt()`：返回 dict（JSON 解密成功时）或 string（非 JSON 时），不再自行格式化
- `decrypt_cli.py --raw`：统一使用 `json_fmt(decrypted)` 格式化输出（dict → 格式化 JSON；JSON string → 重新格式化；普通 string → 保持原样）
- `decrypt_content_direct()`：若 `decrypted` 为 JSON 字符串则转为 dict，供 `json_fmt` 正确处理
- `process_log_content()`：`decrypted_content` 为 dict 时先转为格式化 JSON 字符串，再与 prefix 拼接
- `PlainTextDecryptor.decrypt()`：对 JSON 可解析的明文内容返回 dict（而非原始 string），与 `AESCBCDecryptor.decrypt()` 行为一致，修复明文 JSON 在非匹配行中被错误序列化的 bug

## v2026-05-08

### 改进
- **速度优化**：解密操作改为单工具调用（`exec` + `workdir`），不再写临时脚本文件，减少一次工具调用
- **强化速度原则**：SKILL.md 中明确「速度第一，话少第二，只返回解密结果」，禁止废话和多余分析

## v2026-04-30

### 新增
- **时间过滤功能**：支持按时间过滤日志行
  - 支持格式：`12:17`、`12:17:30`、`2026/04/28 10:16`、`2026-04-28 10:16:30`
  - CLI 使用：`decrypt_cli.py --file <path> 12:17`
  - Python API：`process_file(path, config, parse_time_filter("12:17"))`
- **目录处理**：`process_file()` 支持递归扫描文件夹中的 .txt/.log 文件
- **CHANGELOG.md**：新增变更日志文件
- **JSON 格式化**：解密后的 JSON 内容自动格式化（缩进 2 空格），方便阅读

### 改进
- 返回结果新增 `matched_count` 字段，显示匹配到的时间行数

### 修复
- **日期过滤修复**：`decrypt_cli.py` 现在正确传递文件名给 `process_file()`，确保 `2026/04/28 10:16` 这样的完整日期时间过滤只匹配指定日期的文件
- **完整内容返回**：移除 `original` 字段的 200 字符截断限制，解密结果现在返回完整原始内容和解密后内容
- **原始格式输出**：新增 `--raw` 参数，输出纯解密后的日志文本格式（非 JSON），便于直接阅读
- **强制完整返回原则**：在 SKILL.md 中明确写入「解密出来的内容必须完完整整返回，不能遗漏、省略任何东西」，作为技能核心规则
- **JSON 格式化要求**：解密结果是 JSON 字符串时，必须格式化（缩进 2 空格）后完整返回，禁止以"太长"为由省略字段或不格式化
- **支持直接密文解密**：用户可直接粘贴 base64 密文，技能自动识别并调用 `decrypt_content_direct()` 解密
- **响应速度优化**：默认只返回解密结果，不做分析；用户明确要求时才进行问题诊断和解释
- **删除 quick_decrypt.py**：避免多余脚本，直接使用原有 decrypt_cli.py / decrypt.py

## v2026-04-17

### 初始版本
- 支持多种解密方式（AES-CBC、明文透传）
- 支持文件路径、文件夹路径、.zip 压缩包
- 支持混合日志格式（明文 JSON + 加密 base64）
- 失败时返回原内容并标注
