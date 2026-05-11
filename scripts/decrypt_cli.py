#!/usr/bin/env python3
"""
Log Decryption CLI
命令行工具，支持文件/文件夹/直接密文解密，统一输出格式。

Usage:
  decrypt_cli.py <content>                    - 解密直接密文
  decrypt_cli.py --file <path> [time_filter]  - 解密文件
  decrypt_cli.py --folder <path> [time_filter] - 解密文件夹（所有 .txt/.log）

Output: 统一格式 "[时间戳][FLUTTER][标签] {JSON}"
"""

import sys
import os
import tempfile
import zipfile
import shutil
from pathlib import Path
from typing import Dict, Optional

# Add scripts directory to path
script_dir = Path(__file__).parent
sys.path.insert(0, str(script_dir))

from decrypt import process_log_content, process_file, extract_zip, decrypt_content_direct, parse_time_filter

CONFIG_PATH = script_dir / "config.json"


def get_file_content(file_path: str) -> tuple:
    """
    Get content from file path.
    Returns (files_content, single_name)
    """
    path = Path(file_path)

    if not path.exists():
        return None, None

    if path.is_dir():
        # Folder: collect all .txt and .log files recursively
        files_content = []
        for f in sorted(path.rglob('*.txt')):
            files_content.append((f.name, f.read_text(encoding='utf-8', errors='replace')))
        for f in sorted(path.rglob('*.log')):
            files_content.append((f.name, f.read_text(encoding='utf-8', errors='replace')))
        return files_content, None

    if path.suffix.lower() == '.zip':
        # Zip file: extract to temp dir and process
        with tempfile.TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(path, 'r') as zf:
                zf.extractall(tmpdir)
            files_content = []
            for f in Path(tmpdir).rglob('*.txt'):
                files_content.append((f.name, f.read_text(encoding='utf-8', errors='replace')))
            for f in Path(tmpdir).rglob('*.log'):
                files_content.append((f.name, f.read_text(encoding='utf-8', errors='replace')))
            return files_content, None

    # Regular file
    return [(path.name, path.read_text(encoding='utf-8', errors='replace'))], path.name


def main():
    if len(sys.argv) < 2:
        print("Usage:", file=sys.stderr)
        print("  decrypt_cli.py <content>                    - Decrypt content directly", file=sys.stderr)
        print("  decrypt_cli.py --file <path> [time_filter]  - Decrypt file path", file=sys.stderr)
        print("  decrypt_cli.py --folder <path> [time_filter] - Decrypt folder (all .txt/.log)", file=sys.stderr)
        print("  Time filter: '12:17', '12:17:30', '2026/04/28 10:16'", file=sys.stderr)
        sys.exit(1)

    config_path = str(CONFIG_PATH)
    example_path = config_path + '.example'

    # 检查配置文件是否存在
    if not os.path.exists(config_path):
        print(f"❌ 错误:缺少日志解密配置文件", file=sys.stderr)
        print(f"", file=sys.stderr)
        print(f"请按以下步骤配置:", file=sys.stderr)
        print(f"1. 复制模板:cp {example_path} {config_path}", file=sys.stderr)
        print(f"2. 编辑 {config_path},填入你的解密方法配置", file=sys.stderr)
        print(f"3. 保存后重新运行命令", file=sys.stderr)
        print(f"", file=sys.stderr)
        print(f"配置项说明:", file=sys.stderr)
        print(f"  methods - 解密方法列表,按顺序尝试", file=sys.stderr)
        print(f"  plain   - 明文内容,直接返回", file=sys.stderr)
        print(f"  aes-cbc - AES CBC 模式解密,需要 key 和 iv", file=sys.stderr)
        sys.exit(1)
    
    # Parse command arguments
    args = sys.argv[1:]
    time_filter = None

    # Parse time filter if present (last argument)
    if len(args) >= 2 and not args[-1].startswith('--'):
        time_str = args[-1]
        time_filter = parse_time_filter(time_str)
        if time_filter:
            print(f"Time filter: {time_str}", file=sys.stderr)

    # Unified output function
    def output_results(result):
        for f in result.get('files', []):
            for line in f.get('lines', []):
                if line.get('success'):
                    print(line['decrypted'])
                else:
                    # Try to extract the log header from original, otherwise use full original
                    original = line.get('original', '')
                    if original.strip():
                        print(original)
                print()  # 空行分隔

    if args[0] == '--file':
        # Process file at path
        if len(args) < 2:
            print("Error: --file requires a path", file=sys.stderr)
            sys.exit(1)
        file_path = args[1]

        result = process_file(file_path, config_path, time_filter)
        output_results(result)

    elif args[0] == '--folder':
        # Process folder
        if len(args) < 2:
            print("Error: --folder requires a path", file=sys.stderr)
            sys.exit(1)
        folder_path = args[1]

        result = process_file(folder_path, config_path, time_filter)
        output_results(result)

    else:
        # Treat as content to decrypt directly (single log line)
        content = args[0]
        result = process_log_content(content, config_path)
        for line in result.get('lines', []):
            if line.get('success'):
                print(line['decrypted'])
            else:
                print(line.get('original', content))


if __name__ == '__main__':
    main()
