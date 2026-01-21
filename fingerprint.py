import re
import sys
import base64

def parse_fingerprint(fp: str) -> bytes:
    fp = fp.strip()
    if not fp:
        raise ValueError("Пустой отпечаток")

    # 1. если MD5-отпечаток
    if ':' in fp:
        if re.fullmatch(r'([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}', fp):
            hex_str = fp.replace(':', '')
            if len(hex_str) % 2 != 0:
                raise ValueError(f"Некорректная длина hex: {len(hex_str)} символов. Длина должна быть кратна двум.")
            
            data = bytes.fromhex(hex_str)
            if 12 <= len(data) <= 32:
                print("Распознан MD5-отпечаток")
                return data
            else:
                raise ValueError(f"Длина {len(data)} байт вне диапазона 12-32 байт")

    # 2. если чистый hex (без двоеточий)
    if re.fullmatch(r'[0-9a-fA-F]+', fp):
        hex_str = fp
        if len(hex_str) % 2 != 0:
            raise ValueError(f"Некорректная длина hex: {len(hex_str)} символов. Длина должна быть кратна двум")
        
        data = bytes.fromhex(hex_str)
        if 12 <= len(data) <= 32:
            print("Распознан отпечаток в виде 16-ричной последовательности")
            return data
        else:
            raise ValueError(f"Длина {len(data)} байт вне диапазона 12-32 байт")

    # 3. если SHA256-отпечаток
    fp_clean = re.sub(r'^(SHA256:)', '', fp, flags=re.IGNORECASE).strip()
    fp_clean = re.sub(r'\s+', '', fp_clean)

    try:
        padding = 4 - len(fp_clean) % 4
        if padding != 4:
            fp_clean += '=' * padding

        data = base64.b64decode(fp_clean)
        
        if len(data) == 32:
            print("Распознан SHA256-отпечаток")
            return data
        else:
            raise ValueError(f"Длина {len(data)} байт не равна 32 байтам")   
    except Exception as e:
        raise ValueError(f"Не удалось декодировать base64. {e}")

def visual_fingerprint(digest: bytes) -> str:
    # Размер поля: 17 столбцов (x) × 9 строк (y)
    width = 17
    height = 9
    
    charset = " .o+=*BOX@%&#/^SE"
    
    colors = [
        '',
        '\033[30m',
        '\033[91m',
        '\033[38;5;20m',
        '\033[92m',
        '\033[96m',
        '\033[94m',
        '\033[95m',
        '\033[91;1m',
        '\033[93;1m',
        '\033[92;1m',
        '\033[96;1m',
        '\033[94;1m',
        '\033[95;1m',
        '\033[97;1m',
        '\033[33;1m',
        '\033[32;1m', 
    ]
    
    field = [[0 for _ in range(height)] for _ in range(width)]
    
    x = width // 2
    y = height // 2
    
    # Алгоритм рисования
    for i in range(len(digest)):
        input_byte = digest[i]
        
        for b in range(4):
            x += 1 if (input_byte & 0x1) else -1
            y += 1 if (input_byte & 0x2) else -1
            
            if x < 0: x = 0
            if y < 0: y = 0
            if x >= width: x = width - 1
            if y >= height: y = height - 1
            
            if field[x][y] < len(charset) - 2:
                field[x][y] += 1
            
            input_byte >>= 2
    
    mid_x = width // 2
    mid_y = height // 2
    field[mid_x][mid_y] = -1  # 'S'
    field[x][y] = -2  # 'E'
    
    lines = ["+--[ED25519 256]--+"]
    
    reset_color = '\033[0m'
    for y in range(height):
        line = "|"
        for x in range(width):
            cell = field[x][y]
            if cell == -1:  # 'S'
                line += colors[15] + 'S'
            elif cell == -2:  # 'E'
                line += colors[16] + 'E'
            else:
                color_id = min(cell, len(colors) - 3)
                if color_id < len(colors) and colors[color_id]:
                    line += colors[color_id] + charset[cell]
                else:
                    line += reset_color + charset[cell]
        line += reset_color + "|"
        lines.append(line)
    lines.append("+----[SHA256]-----+")
    
    return "\n".join(lines)


if len(sys.argv) < 2:
    print("Использование: python3 fingerprint.py <отпечаток>")
    exit(0)

fingerprint_str = sys.argv[1]

try:
    data = parse_fingerprint(fingerprint_str)
    print(f"Длина отпечатка: {len(data)} байт")
    print(visual_fingerprint(data))
    
except Exception as e:
    print(f"Ошибка: {e}", file=sys.stderr)
    exit(1)
