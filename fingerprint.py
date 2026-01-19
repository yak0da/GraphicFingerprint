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
    if not (12 <= len(digest) <= 32):
        raise ValueError(f"Длина отпечатка {len(digest)} байт вне допустимого диапазона 12-32 байт")
    
    size = 13 + len(digest) // 2
    if size % 2 == 0:
        size += 1
    size = max(15, min(33, size))

    charset = " .o+=*BOX@%&#/^SE"
    max_level = len(charset) - 3

    field = [[0 for _ in range(size)] for _ in range(size)]

    x = y = size // 2
    field[x][y] = -1

    # Алгоритм рисования псевдографического отпечатка
    for byte in digest:
        for _ in range(4):
            dx = 1 if (byte & 1) else -1
            dy = 1 if (byte & 2) else -1
            x = max(0, min(size - 1, x + dx))
            y = max(0, min(size - 1, y + dy))
            if field[x][y] >= 0:
                field[x][y] = min(max_level, field[x][y] + 1)
            byte >>= 2

    field[x][y] = -2

    title = f"[{size}x{size}]"
    top = "+" + "-" * ((size - len(title)) // 2) + title + "-" * ((size - len(title)) // 2) + "+"
    lines = [top]
    for row in field:
        line = "|" + ''.join('S' if c == -1 else 'E' if c == -2 else charset[c] for c in row) + "|"
        lines.append(line)
    lines.append("+" + "-" * (size) + "+")
    return "\n".join(lines)


if len(sys.argv) < 2:
    print("Использование: python3 fingerprint.py <отпечаток>")
    exit(0)

fingerprint_str = sys.argv[1]

try:
    digest = parse_fingerprint(fingerprint_str)
    print(f"Длина отпечатка: {len(digest)} байт")
    print(visual_fingerprint(digest))
    
except Exception as e:
    print(f"Ошибка: {e}", file=sys.stderr)
    exit(1)

