# Log Decrypt Skill 变更日志

## v2026-05-11 (本次更新)
### 重构
- **统一输出格式**：`decrypt_cli.py` 移除 `--raw` 参数，所有模式（`--file`、`--folder`、直接密文）统一输出格式为 `[时间戳][FLUTTER][标签] {JSON}`
- 移除文件名标题（`=== xxx ===`）
- 移除统计信息（Total/Matched/Decrypted 等）
- 保留空行分隔，保持输出清晰易读
- 简化代码逻辑，`output_results()` 统一处理所有输出

### 新增
- **兼容直接密文无前缀场景**：`decrypt_cli.py` 直接密文模式先调用 `process_log_content`，若无前缀匹配则降级为 `decrypt_content_direct` 直接解密
- **多密文一行支持**：`process_log_content` 自动处理一行内多个空格分隔的 base64 密文（`base64.b64decode` 自动忽略空格）

### 更新
- SKILL.md：移除 `--raw` 参数相关说明
- CHANGELOG.md：添加本次重构记录

## v2026-05-11
### 重构
- **JSON 格式化统一到基类**：`Decryptor` 基类新增 `decrypt_and_format()` 模板方法，调用 `decrypt()` 获取裸字符串后统一 `json_try_fmt()` 格式化。子类 `decrypt()` 只做纯解密（不解压、不格式化），职责单一，扩展新解密方式时无需关心格式化
- **`AESCBCDecryptor.decrypt()`**：`decrypt()` 还原为纯 AES 解密，返回裸字符串；格式化由基类 `decrypt_and_format()` 统一处理
- **`PlainTextDecryptor.decrypt()`**：还原为纯透传，不自行格式化
- **`process_log_content()`**：`decrypted_content` 不再判断 dict 类型（Decryptor 层已保证为格式化字符串），代码更简洁
- **`decrypt_content_direct()`**：简化为一层包装，直接返回 `try_decrypt_with_methods()` 结果
- **移除 `import json`**：`decrypt.py` 不再直接使用 `json` 模块，统一走 `json_utils`
- 新增 `scripts/json_utils.py`：`json_parse`、`json_fmt`、`json_load`、`json_try_fmt` 统一管理所有 JSON 处理逻辑

### 更新
- SKILL.md 简介：新增支持文件内容、直接密文两种输入方式

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
