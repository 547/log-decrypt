#!/usr/bin/env python3
"""
Log Decryption CLI
Simple wrapper for decrypt.py with additional path handling.
Supports: file paths, folder paths, zip files, actual file attachments, time filtering.
"""

import sys
import os
import json
import tempfile
import zipfile
import shutil
from pathlib import Path
from typing import Dict, Optional
from json_utils import json_fmt

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
        print("  decrypt_cli.py --raw --file <path> [time_filter]  - Output raw decrypted text", file=sys.stderr)
        print("  decrypt_cli.py --raw --folder <path> [time_filter] - Output raw decrypted text", file=sys.stderr)
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
    time_filter = None
    raw_mode = False

    # Check for --raw flag
    args = sys.argv[1:]
    if '--raw' in args:
        raw_mode = True
        args.remove('--raw')

    # Parse time filter if present (last argument)
    if len(args) >= 2 and not args[-1].startswith('--'):
        time_str = args[-1]
        time_filter = parse_time_filter(time_str)
        if time_filter:
            print(f"Time filter: {time_str}", file=sys.stderr)

    if args[0] == '--file':
        # Process file at path
        if len(args) < 2:
            print("Error: --file requires a path", file=sys.stderr)
            sys.exit(1)
        file_path = args[1]

        result = process_file(file_path, config_path, time_filter)

        if raw_mode:
            # Output raw decrypted text format
            for f in result.get('files', []):
                if f.get('matched_count', 0) > 0 or not time_filter:
                    for line in f.get('lines', []):
                        if line.get('success'):
                            print(line['decrypted'])
        else:
            print(json_fmt(result))

    elif args[0] == '--folder':
        # Process folder
        if len(args) < 2:
            print("Error: --folder requires a path", file=sys.stderr)
            sys.exit(1)
        folder_path = args[1]

        result = process_file(folder_path, config_path, time_filter)

        if raw_mode:
            # Output raw decrypted text format
            for f in result.get('files', []):
                if f.get('matched_count', 0) > 0 or not time_filter:
                    for line in f.get('lines', []):
                        if line.get('success'):
                            print(line['decrypted'])
        else:
            print(json_fmt(result))

    else:
        # Treat as content to decrypt directly
        content = args[0]
        result = decrypt_content_direct(content, config_path)

        if raw_mode:
            decrypted = result.get('decrypted')
            print(decrypted if decrypted else result.get('original', content))
        else:
            print(json_fmt(result))


if __name__ == '__main__':
    main()
