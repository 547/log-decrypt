#!/usr/bin/env python3
"""
Log Decryption Script
Supports multiple decryption methods in configurable order.
Handles log files with mixed plaintext and encrypted content.
Supports time-based filtering.
"""

import sys
import json
import base64
import zipfile
import tempfile
import os
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from json_utils import json_fmt, json_parse, json_try_fmt, json_load

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class Decryptor:
    """Base decryptor class"""
    
    def decrypt(self, ciphertext: str) -> Optional[str]:
        raise NotImplementedError
    
    def can_handle(self, content: str) -> bool:
        """Check if this decryptor can handle the content"""
        return True
    
    def is_likely_plaintext(self, content: str) -> bool:
        """Check if content looks like plaintext (not encrypted)"""
        try:
            parsed, _ = json_parse(content)
            if parsed:
                return True
        except:
            pass
        
        try:
            if len(content) < 500:
                decoded = content.decode('utf-8') if isinstance(content, bytes) else content
                printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / max(len(decoded), 1)
                if printable_ratio > 0.95:
                    return True
            return False
        except:
            return False


class AESCBCDecryptor(Decryptor):
    """AES CBC mode decryptor"""
    
    def __init__(self, config: Dict[str, Any]):
        self.key = config.get('key', '').encode('utf-8')
        self.iv = config.get('iv', '').encode('utf-8')
        self.output_encoding = config.get('outputEncoding', 'utf-8')
    
    def can_handle(self, content: str) -> bool:
        if not content:
            return False
        try:
            decoded = base64.b64decode(content)
            return len(decoded) >= 16
        except:
            return False
    
    def decrypt(self, ciphertext: str) -> Optional[str]:
        if not HAS_CRYPTOGRAPHY:
            return None
        
        try:
            encrypted_data = base64.b64decode(ciphertext)
            if len(encrypted_data) % 16 != 0:
                return None
            
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(self.iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data.decode(self.output_encoding)
        except:
            return None


class PlainTextDecryptor(Decryptor):
    """Passthrough for plaintext content"""
    
    def can_handle(self, content: str) -> bool:
        try:
            base64.b64decode(content)
            return False
        except:
            pass
        return self.is_likely_plaintext(content)
    
    def decrypt(self, content: str) -> Optional[str]:
        if self.can_handle(content):
            return content
        return None


def load_config(config_path: str) -> Dict[str, Any]:
    """读取配置文件，不存在则报错提示用户配置。"""
    if not os.path.exists(config_path):
        example_path = config_path + '.example'
        print(f"❌ 错误：缺少日志解密配置文件", file=sys.stderr)
        print(f"", file=sys.stderr)
        print(f"请按以下步骤配置：", file=sys.stderr)
        print(f"1. 复制模板：cp {example_path} {config_path}", file=sys.stderr)
        print(f"2. 编辑 {config_path}，填入你的解密方法配置", file=sys.stderr)
        print(f"3. 保存后重新运行命令", file=sys.stderr)
        print(f"", file=sys.stderr)
        print(f"配置项说明：", file=sys.stderr)
        print(f"  methods - 解密方法列表，按顺序尝试", file=sys.stderr)
        print(f"  plain   - 明文内容，直接返回", file=sys.stderr)
        print(f"  aes-cbc - AES CBC 模式解密，需要 key 和 iv", file=sys.stderr)
        sys.exit(1)
    
    with open(config_path, 'r', encoding='utf-8') as f:
        parsed, err = json_load(f)
    if err is not None:
        print(f"❌ 错误：配置文件格式错误 - {err}", file=sys.stderr)
        sys.exit(1)
    return parsed


def create_decryptor(method: str, config: Dict[str, Any]) -> Optional[Decryptor]:
    if method == 'aes-cbc':
        return AESCBCDecryptor(config)
    elif method == 'plain':
        return PlainTextDecryptor()
    return None


def try_decrypt_with_methods(content: str, config_path: str) -> Dict[str, Any]:
    config = load_config(config_path)
    methods = config.get('methods', [])
    tried_methods = []
    
    for method_config in methods:
        method_name = method_config.get('name')
        method_params = method_config.get('params', {})
        
        decryptor = create_decryptor(method_name, method_params)
        if not decryptor:
            continue
        
        if not decryptor.can_handle(content):
            tried_methods.append(method_name)
            continue
        
        result = decryptor.decrypt(content)
        if result is not None:
            return {
                'success': True,
                'decrypted': result,
                'method': method_name,
                'failed': False
            }
        
        tried_methods.append(method_name)
    
    return {
        'success': False,
        'decrypted': content,
        'method': ', '.join(tried_methods) if tried_methods else 'none',
        'failed': True,
        'note': '解密失败，返回原始密文'
    }


def extract_zip(zip_path: str, extract_dir: str) -> List[str]:
    extracted = []
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(extract_dir)
        for name in zf.namelist():
            extracted.append(os.path.join(extract_dir, name))
    return extracted


# Log line pattern: [timestamp][TYPE] content
LOG_PATTERN = re.compile(r'^(\[\d{2}:\d{2}:\d{2}\.\d{3}\]\[[^\]]+\]\[[^\]]+\]\s*)(.*)$', re.DOTALL)

# Time patterns for matching
TIME_PATTERN_HHMM = re.compile(r'^(\d{1,2}):(\d{2})$')
TIME_PATTERN_HHMMSS = re.compile(r'^(\d{1,2}):(\d{2}):(\d{2})$')
TIME_PATTERN_FULL = re.compile(r'^(\d{4})[/-](\d{1,2})[/-](\d{1,2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?$')


def parse_time_filter(time_str: str) -> Dict[str, Any]:
    """
    Parse time filter string into components.
    Supports: "12:17", "12:17:30", "2026/04/28 10:16", "2026-04-28 10:16:30"
    Returns: {'type': 'time_only'|'full', 'hour': int, 'minute': int, 'second': int|None, 
              'year': int|None, 'month': int|None, 'day': int|None}
    """
    time_str = time_str.strip()
    
    # Try full datetime: 2026/04/28 10:16 or 2026-04-28 10:16:30
    m = TIME_PATTERN_FULL.match(time_str)
    if m:
        return {
            'type': 'full',
            'year': int(m.group(1)),
            'month': int(m.group(2)),
            'day': int(m.group(3)),
            'hour': int(m.group(4)),
            'minute': int(m.group(5)),
            'second': int(m.group(6)) if m.group(6) else None
        }
    
    # Try HH:MM:SS
    m = TIME_PATTERN_HHMMSS.match(time_str)
    if m:
        return {
            'type': 'time_only',
            'year': None, 'month': None, 'day': None,
            'hour': int(m.group(1)),
            'minute': int(m.group(2)),
            'second': int(m.group(3))
        }
    
    # Try HH:MM
    m = TIME_PATTERN_HHMM.match(time_str)
    if m:
        return {
            'type': 'time_only',
            'year': None, 'month': None, 'day': None,
            'hour': int(m.group(1)),
            'minute': int(m.group(2)),
            'second': None
        }
    
    return None


def extract_date_from_filename(filename: str) -> Optional[Dict[str, int]]:
    """Extract date from filename like log_20260428.txt -> {year:2026, month:4, day:28}"""
    # Pattern: log_YYYYMMDD.txt or similar
    m = re.search(r'(\d{4})(\d{2})(\d{2})', filename)
    if m:
        return {
            'year': int(m.group(1)),
            'month': int(m.group(2)),
            'day': int(m.group(3))
        }
    return None


def line_matches_time(line: str, time_filter: Dict[str, Any], filename: str = '') -> bool:
    """Check if a log line matches the time filter."""
    # Extract time from log line: [HH:MM:SS.mmm]
    time_match = re.search(r'\[(\d{2}):(\d{2}):(\d{2})\.(\d{3})\]', line)
    if not time_match:
        return False
    
    line_hour = int(time_match.group(1))
    line_minute = int(time_match.group(2))
    line_second = int(time_match.group(3))
    
    # Check time components
    if line_hour != time_filter['hour']:
        return False
    if line_minute != time_filter['minute']:
        return False
    if time_filter['second'] is not None and line_second != time_filter['second']:
        return False
    
    # If full date filter, also check date from filename
    if time_filter['type'] == 'full':
        file_date = extract_date_from_filename(filename)
        if file_date:
            if file_date['year'] != time_filter['year']:
                return False
            if file_date['month'] != time_filter['month']:
                return False
            if file_date['day'] != time_filter['day']:
                return False
    
    return True



def process_log_content(content: str, config_path: str, time_filter: Optional[Dict[str, Any]] = None, filename: str = '') -> Dict[str, Any]:
    """
    Process log content line by line.
    If time_filter is provided, only process lines matching that time.
    """
    lines = content.split('\n')
    results = []
    matched_count = 0
    
    for line in lines:
        match = LOG_PATTERN.match(line)
        if match:
            prefix = match.group(1)
            data = match.group(2)
            
            # Check time filter (pass filename for date matching)
            if time_filter and not line_matches_time(line, time_filter, filename):
                continue
            
            matched_count += 1
            result = try_decrypt_with_methods(data.strip(), config_path)
            
            if result['success']:
                # Format JSON if decrypted content is JSON
                decrypted_content = json_try_fmt(result['decrypted'])
                decrypted_line = prefix + decrypted_content
                results.append({
                    'original': line,
                    'decrypted': decrypted_line,
                    'method': result['method'],
                    'success': True
                })
            elif result['failed'] and result.get('note'):
                results.append({
                    'original': line,
                    'decrypted': line,
                    'method': result['method'],
                    'success': False,
                    'note': result['note']
                })
            else:
                results.append({
                    'original': line,
                    'decrypted': line,
                    'method': 'plain',
                    'success': True
                })
        else:
            # Non-matching lines (if time filter active, skip them)
            if time_filter:
                continue
            results.append({
                'original': line[:200] + '...' if len(line) > 200 else line,
                'decrypted': line,
                'method': 'plain',
                'success': True
            })
    
    return {
        'total_lines': len(lines),
        'matched_count': matched_count,
        'decrypted_count': sum(1 for r in results if r['success'] and r['method'] != 'plain'),
        'plain_count': sum(1 for r in results if r['method'] == 'plain'),
        'failed_count': sum(1 for r in results if r.get('note') == '解密失败，返回原始密文'),
        'lines': results
    }


def process_file(file_path: str, config_path: str, time_filter: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Process a file, folder, or zip: read content, decrypt with optional time filter."""
    path = Path(file_path)
    
    # Handle directory
    if path.is_dir():
        all_results = []
        for f in sorted(path.rglob('*.txt')):
            content = f.read_text(encoding='utf-8', errors='replace')
            result = process_log_content(content, config_path, time_filter, f.name)
            result['file'] = f.name
            all_results.append(result)
        for f in sorted(path.rglob('*.log')):
            content = f.read_text(encoding='utf-8', errors='replace')
            result = process_log_content(content, config_path, time_filter, f.name)
            result['file'] = f.name
            all_results.append(result)
        return {'files': all_results}
    
    if path.suffix.lower() == '.zip':
        with tempfile.TemporaryDirectory() as tmpdir:
            extracted = extract_zip(str(path), tmpdir)
            all_results = []
            for f in extracted:
                with open(f, 'r', encoding='utf-8', errors='replace') as fp:
                    content = fp.read()
                result = process_log_content(content, config_path, time_filter, os.path.basename(f))
                result['file'] = os.path.basename(f)
                all_results.append(result)
            return {'files': all_results}
    else:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        result = process_log_content(content, config_path, time_filter, path.name)
        result['file'] = path.name
        return {'files': [result]}


def decrypt_content_direct(content: str, config_path: str) -> Dict[str, Any]:
    result = try_decrypt_with_methods(content, config_path)
    if result.get('success') and result.get('decrypted'):
        result['decrypted'] = json_try_fmt(result['decrypted'])
    return result


def main():
    if len(sys.argv) < 3:
        print("Usage: decrypt.py <file_path> <config_path> [time_filter]", file=sys.stderr)
        print("  time_filter: '12:17', '12:17:30', '2026/04/28 10:16'", file=sys.stderr)
        sys.exit(1)
    
    file_path = sys.argv[1]
    config_path = sys.argv[2]
    
    # Parse optional time filter
    time_filter = None
    if len(sys.argv) >= 4:
        time_str = sys.argv[3]
        time_filter = parse_time_filter(time_str)
        if time_filter:
            print(f"Time filter: {time_str}", file=sys.stderr)
    
    result = process_file(file_path, config_path, time_filter)
    print(json_fmt(result))


if __name__ == '__main__':
    main()
