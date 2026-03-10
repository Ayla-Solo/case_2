import re
import base64
import codecs
from datetime import datetime


# ________________________cards____role_1________________
def luhn_check(card_number):
    digits = [int(d) for d in card_number]
    checksum = 0
    reverse_digits = digits[::-1]

    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def find_and_validate_credit_cards(filename):
    with open(filename, "r", encoding="utf-8") as file:
        text = file.read()

    pattern = r'\b(?:\d[ -]?){16}\b'
    matches = re.findall(pattern, text)

    valid_cards = []
    invalid_cards = []

    for match in matches:
        clean_number = re.sub(r'\D', '', match)

        if len(clean_number) == 16 and luhn_check(clean_number):
            valid_cards.append(clean_number)
        else:
            invalid_cards.append(clean_number)

    # with open("/Users/olga/Desktop/result11.txt", "w") as f:
    with open("result11.txt", "w") as f:
        for card in valid_cards:
            f.write(card + "\n")

        for card in invalid_cards:
            f.write(card + "\n")

    return {"valid": valid_cards, "invalid": invalid_cards}


# __________role_2_____
PATTERNS = {

    'Generic Secret (Key/Pass)':
        r'(?i)(api_key|secret|password|token|auth|pwd)'
        r'[\s:="\' ]+([a-zA-Z0-9_\-\.]{12,})',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'Private Key': r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
    'High Entropy String (Potential Key)': r'[a-zA-Z0-9/\+=]{32,}'
}


def find_secrets(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    found_any = False

    for name, pattern in PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            found_any = True
            if name == 'Generic Secret (Key/Pass)':

                field = match.group(1)
                secret_value = match.group(2)

                print(f" {secret_value}")
            else:
                val = match.group(0)
                print(f" {val[:80]}")
    if not found_any:
        print('Секреты не найдены')


find_secrets('777.txt')


# ______role_3_________
def find_system_info(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        text = file.read()

    num = r'(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'

    ip_pattern = r'\b(' + num + r'\.' + num + r'\.' + num + r'\.' + num + r')\b'

    email_pattern = r'\b[a-zA-Z0-9]+([._+%-][a-zA-Z0-9]+)*@[a-zA-Z0-9]+([.-][a-zA-Z0-9]+)*\.[a-zA-Z]{2,}\b'

    file_pattern = r'\b[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\b'

    found_ip = [match.group(0) for match in re.finditer(ip_pattern, text)]

    found_file = re.findall(file_pattern, text)
    found_email = [match.group(0) for match in re.finditer(email_pattern, text)]

    result = {
        'ip': list(dict.fromkeys(found_ip)),
        'file': list(dict.fromkeys(found_file)),
        'email': list(dict.fromkeys(found_email))
    }

    return result


result = find_system_info("666.txt")

for value in result['ip']:
    print(value)
for value in result['file']:
    print(value)
for value in result['email']:
    print(value)


# _____role_4___________
def decode_messages(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        text = file.read()

    result = {'base64': [], 'hex': [], 'rot13': []}

    # Base64
    base64_pattern = r'[A-Za-z0-9+/]{4,}(?:=){0,2}'
    base64_matches = re.findall(base64_pattern, text)
    for encoded in base64_matches:
        try:
            decoded = base64.b64decode(encoded).decode('utf-8')
            result['base64'].append(decoded)
        except:
            pass

    # HEX
    hex_pattern1 = r'0x[0-9A-Fa-f]+'
    hex_pattern2 = r'(?:\\x[0-9A-Fa-f]{2})+'
    hex_matches = re.findall(hex_pattern1, text) + re.findall(hex_pattern2, text)
    for encoded in hex_matches:
        try:
            if encoded.startswith('0x'):
                hex_str = encoded[2:]
                byte_data = bytes.fromhex(hex_str)
                decoded = byte_data.decode('utf-8')
                result['hex'].append(decoded)
            elif encoded.startswith('\\x'):
                hex_parts = encoded.split('\\x')[1:]
                byte_data = bytes([int(part, 16) for part in hex_parts])
                decoded = byte_data.decode('utf-8')
                result['hex'].append(decoded)
        except:
            pass

    # ROT13
    rot13_pattern = r'[A-Za-z\s]+'
    rot13_candidates = re.findall(rot13_pattern, text)
    for candidate in rot13_candidates:
        candidate = candidate.strip()
        if len(candidate) > 3:
            try:
                decoded = codecs.decode(candidate, 'rot_13')
                if re.match(r'^[A-Za-z\s]+$', decoded):
                    result['rot13'].append(decoded)
            except:
                pass

    result['base64'] = list(dict.fromkeys(result['base64']))
    result['hex'] = list(dict.fromkeys(result['hex']))
    result['rot13'] = list(dict.fromkeys(result['rot13']))

    return result


result = decode_messages("666.txt")

print("Base64 расшифровки:")
for value in result['base64']:
    print(f"  {value}")

print("\nHex расшифровки:")
for value in result['hex']:
    print(f"  {value}")

print("\nROT13 расшифровки:")
for value in result['rot13']:
    print(f"  {value}")


# _______role_5_______
def analyze_logs(log_file_name):
    with open(log_file_name, 'r', encoding='utf-8') as file:
        log_text = file.read()

    results = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }

    patterns = {
        'sql_injections': r"(?i)(UNION\s+SELECT|SELECT.*FROM|OR\s+1=1|DROP\s+TABLE|--|')",  # шаблоны
        'xss_attempts': r"(?i)(<script|alert\(|onload=|javascript:)",
        'suspicious_user_agents': r"(?i)(sqlmap|nmap|nikto|acunetix|gobuster|python-requests)",
        'failed_logins': r"(?i)(failed login|authentication failure|invalid password|401)"
    }

    for line in log_text.splitlines():

        for category, pattern in patterns.items():
            if re.search(pattern, line):
                results[category].append(line.strip())

    return results


res = analyze_logs('777.txt')
for st in res:
    print(res[st])


# ________________role_6_____
# ТВОЯ функция Луна
def luhn_check(card_number: str) -> bool:
    """
    Проверка номера карты по алгоритму Луна
    """
    digits = [int(d) for d in card_number]
    checksum = 0
    reverse_digits = digits[::-1]

    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


# Функция валидации ИНН
def validate_inn(inn):
    """Полная валидация ИНН по ГОСТ 28147-89"""
    if not inn.isdigit():
        return False

    if len(inn) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(int(inn[i]) * weights[i] for i in range(9)) % 11 % 10
        return checksum == int(inn[9])

    elif len(inn) == 12:
        weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum1 = sum(int(inn[i]) * weights1[i] for i in range(10)) % 11 % 10
        if checksum1 != int(inn[10]):
            return False

        weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum2 = sum(int(inn[i]) * weights2[i] for i in range(11)) % 11 % 10
        return checksum2 == int(inn[11])

    return False


def normalize_and_validate(text):
    """
    Приводит данные к единому формату и проверяет их на корректность.
    """
    results = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }

    text_lower = text.lower()

    # 1. ТЕЛЕФОНЫ: РФ (+7...) и E.164 формат
    phone_patterns = [
        r'(\+?7|8|7)[\s\-\.]?(\(?\d{3}\)?)[\s\-\.]?(\d{3})[\s\-\.]?(\d{2})[\s\-\.]?(\d{2})',
        r'(\+?7|8|7)[\s\-\.]?(\d{3})[\s\-\.]?(\d{3})[\s\-\.]?(\d{4})',
        r'(\+?7|8|7)(\d{10})',
        r'\+?(\d{10,15})'
    ]

    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            phone_digits = ''.join(filter(str.isdigit, ''.join(match)))

            if len(phone_digits) in [10, 11] and phone_digits[:2] in ['7', '8']:
                if len(phone_digits) == 10:
                    phone_digits = '7' + phone_digits
                elif phone_digits.startswith('8'):
                    phone_digits = phone_digits.replace('8', '7', 1)

                normalized_phone = '+' + phone_digits
                if normalized_phone not in results['phones']['valid']:
                    results['phones']['valid'].append(normalized_phone)

            elif 10 <= len(phone_digits) <= 15 and not phone_digits.startswith('7'):
                normalized_phone = '+' + phone_digits[:15]
                if normalized_phone not in results['phones']['valid']:
                    results['phones']['valid'].append(normalized_phone)
            else:
                invalid_phone = ''.join(match)
                if invalid_phone not in results['phones']['invalid']:
                    results['phones']['invalid'].append(invalid_phone)

    # 2. ДАТЫ: Нормализация в ISO 8601
    date_patterns = [
        r'(\d{1,2})\.(\d{1,2})\.(\d{4})',
        r'(\d{1,2})/(\d{1,2})/(\d{4})',
        r'(\d{4})-(\d{1,2})-(\d{1,2})',
        r'(\d{4})/(\d{1,2})/(\d{1,2})',
        r'(\d{2})\.(\d{2})\.(\d{2})',
        r'(\d{1,2})\s*(янв|фев|мар|апр|май|июн|июл|авг|сен|окт|ноя|дек)\s*(\d{4})'
    ]

    month_map = {
        'янв': 1, 'фев': 2, 'мар': 3, 'апр': 4, 'май': 5, 'июн': 6,
        'июл': 7, 'авг': 8, 'сен': 9, 'окт': 10, 'ноя': 11, 'дек': 12
    }

    for pattern in date_patterns:
        matches = re.findall(pattern, text_lower)
        for match in matches:
            try:
                if len(match) == 3 and isinstance(match[2], str) and len(match[2]) == 2:
                    day, month, year = int(match[0]), int(match[1]), 2000 + int(match[2])
                elif len(match) == 3 and match[2] in month_map:
                    day, month, year = int(match[0]), month_map[match[2]], int(match[-1])
                else:
                    day, month, year = map(int, match[:3])

                dt = datetime(year, month, day)
                normalized = dt.strftime('%Y-%m-%d')

                if normalized not in results['dates']['normalized']:
                    results['dates']['normalized'].append(normalized)

            except (ValueError, IndexError):
                invalid_date = '.'.join([str(x) for x in match])
                if invalid_date not in results['dates']['invalid']:
                    results['dates']['invalid'].append(invalid_date)

    # 3. ИНН
    inn_pattern = r'\b(\d{10}|\d{12})\b'
    raw_inns = re.findall(inn_pattern, text)

    for inn in raw_inns:
        if validate_inn(inn):
            if inn not in results['inn']['valid']:
                results['inn']['valid'].append(inn)
        else:
            if inn not in results['inn']['invalid']:
                results['inn']['invalid'].append(inn)

    # 4. КАРТЫ
    card_pattern = r'\b(?:\d[ -]?){13,19}\b'
    raw_cards = re.findall(card_pattern, text)

    for card in raw_cards:
        digits_only = ''.join(filter(str.isdigit, card))
        if 13 <= len(digits_only) <= 19 and luhn_check(digits_only):
            masked = '**** **** **** ' + digits_only[-4:]
            if masked not in results['cards']['valid']:
                results['cards']['valid'].append(masked)
        else:
            masked_invalid = '**** **** **** ' + digits_only[-4:] if len(digits_only) >= 4 else card
            if masked_invalid not in results['cards']['invalid']:
                results['cards']['invalid'].append(masked_invalid)

    # ВАЖНО: ВОЗВРАЩАЕМ РЕЗУЛЬТАТ!
    return results


# 🔴 ОСНОВНАЯ ЧАСТЬ - ЧИТАЕМ ФАЙЛ И ВЫВОДИМ РЕЗУЛЬТАТ
if __name__ == "__main__":
    # Читаем файл 666.txt
    with open('666.txt', 'r', encoding='utf-8') as file:
        text = file.read()

    # Вызываем функцию
    result = normalize_and_validate(text)

    # Выводим результат красиво
    print("РЕЗУЛЬТАТ ОБРАБОТКИ:")
    print("=" * 50)

    for category, data in result.items():
        print(f"\n{category.upper()}:")
        for status, items in data.items():
            if items:
                print(f"  {status}:")
                for item in items:
                    print(f"    - {item}")


# __________data comparison________________
def compare_files(file1, file2):
    with open(file1, "r", encoding="utf-8") as f1:
        set1 = {line.strip() for line in f1}

    with open(file2, "r", encoding="utf-8") as f2:
        set2 = {line.strip() for line in f2}

    only_in_file1 = set1 - set2
    only_in_file2 = set2 - set1

    if not only_in_file1 and not only_in_file2:
        print("Файлы совпадают по содержимому (порядок игнорируется)")
        return

    if only_in_file1:
        print("Есть только в result11.txt:")
        for line in only_in_file1:
            print(line)

    if only_in_file2:
        print(f"\nЕсть только в {file2} :")
        for line in only_in_file2:
            print(line)


if __name__ == "__main__":
    # filename = "/Users/olga/Desktop/666.txt"
    filename = "666.txt"
    result = find_and_validate_credit_cards(filename)
    # на выходе имеем созданный файл result11.txt
    for i in range(1, 2):
        # file1 = "/Users/olga/Desktop/result11.txt"
        # file2 = "/Users/olga/Desktop/result"+ str(i) + ".txt"
        file1 = "result11.txt"
        file2 = "result" + str(i) + ".txt"
        comparison = compare_files(file1, file2)
