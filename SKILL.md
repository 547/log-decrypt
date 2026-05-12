---
name: log-decrypt
description: 解密日志文件技能包。支持文件路径、文件夹路径、.zip压缩包、文件内容、直接密文，自动解密日志内容。支持按时间过滤（如12:17或2026/04/28 10:16）。支持多种解密方式（数组配置），失败时返回原内容并标注。
---

# Log Decrypt Skill

## ⚠️ 核心原则：完整返回，绝不遗漏

**解密出来的内容必须完完整整返回，不能遗漏、省略任何东西。**

这是用于排查 bug 的工具，任何遗漏都可能影响诊断。包括但不限于：
- 完整的 JSON 字段（即使看起来不重要的字段）
- 完整的错误堆栈（stackTrace）
- 完整的错误信息（errorMessage）
- 完整的请求/响应内容
- 完整的头部信息

**JSON 格式化要求：**
- ✅ 如果解密结果是 JSON 字符串，**必须格式化后返回**（缩进 2 空格）
- ✅ 格式化后的 JSON 也必须**完整返回所有字段**，不能省略
- ❌ 禁止以"太长"为由不格式化或直接返回压缩 JSON

**禁止行为：**
- ❌ 截断长内容（如只显示前 200 字符）
- ❌ 省略某些字段（如 error、stackTrace）
- ❌ 用 "..." 代替部分内容
- ❌ 为了"简洁"而省略任何数据
- ❌ JSON 结果不格式化直接返回压缩字符串

## 功能

1. 支持多种输入方式：
   - **文件路径**：如 `/Users/momo/Desktop/all_logs.txt`
   - **文件夹路径**：如 `/Users/momo/Desktop/logs_1777355676654`（自动扫描所有 .txt/.log 文件）
   - **.zip 压缩包**：如 `/Users/momo/Desktop/logs_1777342038575.zip`（自动解压后处理）
   - **文件内容**：直接发送文件内容或密文
   - **直接密文**：用户直接粘贴一段 base64 密文，直接调用 `decrypt_content_direct()` 解密

2. 支持按时间过滤：
   - 格式1：`12:17`（匹配该时间点的日志）
   - 格式2：`12:17:30`（精确到秒）
   - 格式3：`2026/04/28 10:16`（指定日期和时间）
   - 格式4：`2026-04-28 10:16:30`（完整日期时间）

3. ZIP 文件自动解压

4. 读取内容，尝试解密（支持多种解密方式）

5. 返回解密结果或原文（标注失败）——**必须完整返回，不能遗漏任何字段或内容**

## 响应速度优化原则（最重要）

**速度第一，话少第二，只返回解密结果。**

- ✅ 解密成功 → 直接返回解密后的内容（格式化 JSON 后直接输出）
- ❌ **禁止主动分析、解释、总结**
- ❌ **禁止添加"关键信息"、"问题分析"等额外内容**
- ❌ **禁止生成表格或结构化分析**
- ❌ **禁止废话**（如"解密成功"、"以下是结果"等）

**用户明确要求分析时**，才进行问题诊断和解释。

**核心口诀：执行脚本 → 返回结果 → 闭嘴**

## 使用方式

### 方式1：通过 SKILL.md 触发（推荐）

当用户发送文件路径、文件夹路径、文件内容或密文时，自动调用技能处理。

**处理逻辑：**
1. 如果用户发送的是**文件路径**（如 `/Users/momo/Desktop/all_logs.txt`）→ 用 `--file` 处理
2. 如果用户发送的是**文件夹路径** → 用 `--folder` 处理
3. 如果用户发送的是**文件内容**（包含多行日志格式）→ 用 `process_log_content()` 处理
4. 如果用户发送的是**纯密文**（单行 base64 字符串，无日志前缀）→ 直接用 `decrypt_content_direct()` 解密

### 方式2：命令行调用

```bash
# 解密整个文件
python3 scripts/decrypt_cli.py --file /Users/momo/Desktop/all_logs.txt

# 按时间过滤解密
python3 scripts/decrypt_cli.py --file /Users/momo/Desktop/all_logs.txt 12:17
python3 scripts/decrypt_cli.py --file /Users/momo/Desktop/all_logs.txt 2026/04/28 10:16

# 解密文件夹（处理所有 .txt/.log 文件）
python3 scripts/decrypt_cli.py --folder /Users/momo/Desktop/logs_1777355676654

# 解密文件夹并过滤时间
python3 scripts/decrypt_cli.py --folder /Users/momo/Desktop/logs_1777355676654 2026/04/28 10:16

# 解密压缩包
python3 scripts/decrypt_cli.py --file /Users/momo/Desktop/logs_1777342038575.zip

# 解密字符串内容（直接密文）
python3 scripts/decrypt_cli.py "<base64_encrypted_string>"
```

### 方式3：Python 模块调用

```python
from decrypt import process_log_content, process_file, decrypt_content_direct, parse_time_filter

# 解密字符串
result = decrypt_content_direct("base64字符串", "scripts/config.json")

# 处理文件内容（全部）
result = process_file("/path/to/file.txt", "scripts/config.json")

# 按时间过滤处理
time_filter = parse_time_filter("12:17")
result = process_file("/path/to/file.txt", "scripts/config.json", time_filter)
```

## 核心脚本

| 脚本 | 说明 |
|------|------|
| `decrypt.py` | 解密核心逻辑，支持时间过滤 |
| `decrypt_cli.py` | 命令行入口，支持文件/文件夹/压缩包/时间过滤 |


## 解密配置

`scripts/config.json` — 可配置的解密方式数组

```json
{
  "methods": [
    {
      "name": "plain",
      "description": "明文内容，直接返回",
      "params": {}
    },
    {
      "name": "aes-cbc",
      "description": "AES CBC 解密",
      "params": {
        "key": "rms-aes32-long-secret-key-string",
        "iv": "rms-aes16-longIV",
        "inputEncoding": "base64",
        "outputEncoding": "utf-8",
        "padding": "pkcs7"
      }
    }
  ]
}
```

### 支持的解密方式

| name | 说明 | 必需参数 |
|------|------|----------|
| `plain` | 明文内容，直接返回 | 无 |
| `aes-cbc` | AES CBC 模式解密 | key, iv |

### 添加新解密方式

1. 在 `decrypt.py` 中创建新的 Decryptor 类（如 `AESGCMDecryptor`）
2. 在 `create_decryptor()` 函数中注册
3. 在 `config.json` 中添加配置项

## 日志格式

技能自动识别以下日志格式，支持两种时间戳格式：

```
[HH:mm:ss.SSS][FLUTTER][COMMON] {"message":"..."}           <- 明文（时间戳格式1）
[HH:mm:ss.SSS][FLUTTER][RESPONSE] base64_encrypted_data     <- 加密内容（时间戳格式1）
[YYYY-MM-DD HH:mm:ss.SSS][FLUTTER][REQUEST] base64_encrypted_data  <- 加密内容（时间戳格式2）
[YYYY-MM-DD HH:mm:ss.SSS][FLUTTER][ERROR] {"error":"..."}  <- 明文（时间戳格式2）
```

**时间戳格式说明：**
- 格式1：`[HH:mm:ss.SSS]` 如 `[12:17:10.800]`
- 格式2：`[YYYY-MM-DD HH:mm:ss.SSS]` 如 `[2026-05-12 09:01:01.952]`
- 两种格式可混用，技能自动识别

## 返回格式（带时间过滤）

```json
{
  "files": [
    {
      "file": "all_logs.txt",
      "total_lines": 58,
      "matched_count": 2,
      "decrypted_count": 2,
      "plain_count": 0,
      "failed_count": 0,
      "lines": [
        {
          "original": "[12:17:10.800][FLUTTER][RESPONSE] WAoy3mY...",
          "decrypted": "[12:17:10.800][FLUTTER][RESPONSE] {\"method\":\"GET\",...}",
          "method": "aes-cbc",
          "success": true
        }
      ]
    }
  ]
}
```

### 成功解密

```json
{
  "success": true,
  "decrypted": "解密后内容",
  "method": "aes-cbc",
  "failed": false
}
```

### 解密失败

```json
{
  "success": false,
  "decrypted": "原始密文",
  "method": "plain, aes-cbc",
  "failed": true,
  "note": "解密失败，返回原始密文"
}
```

## 注意事项

- 依赖 Python 库：`cryptography`（AES 解密必需）
- 解密方式按配置数组顺序尝试，直到成功
- 所有方式都失败时，返回原密文并标注失败
- 文件夹处理：递归扫描所有 .txt 和 .log 文件
- 时间过滤：匹配日志行中的 `[HH:MM:SS.mmm]` 时间戳

## ⚠️ 再次强调：完整返回 + JSON 格式化原则

**任何情况下，解密结果必须完整返回，禁止任何形式的截断或省略。**

**JSON 必须格式化：**
- 解密结果是 JSON 时，必须格式化输出（缩进 2 空格）
- JSON 格式化后的 JSON 同样必须完整，不能省略任何字段
- 这是 bug 排查的关键工具，数据完整性直接影响问题定位
