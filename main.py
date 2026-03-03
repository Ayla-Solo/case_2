def normalize_and_validate(text):
    """
    Приводит данные к единому формату и проверяет их на корректность.

    Возвращает: {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }

    Логика валидации:
    # Телефоны: Фильтр РФ (+7...) и международные E.164
    # Даты: Конвертация всех форматов в ISO 8601 (YYYY-MM-DD)
    # ИНН: Проверка длины (10 или 12 цифр) и контрольных сумм по ГОСТ 28147-89
    # Карты: Повторная проверка алгоритма Луна
    """
    import re
    from datetime import datetime

    results = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }

    text_lower = text.lower()

    # 1. ТЕЛЕФОНЫ: РФ (+7...) и E.164 формат
    phone_patterns = [
        r'(\+?7|8|7)[\s\-\.]?(\(?\d{3}\)?)[\s\-\.]?(\d{3})[\s\-\.]?(\d{2})[\s\-\.]?(\d{2})',  # +7 (999) 123-45-67
        r'(\+?7|8|7)[\s\-\.]?(\d{3})[\s\-\.]?(\d{3})[\s\-\.]?(\d{4})',  # 8 999 123 4567
        r'(\+?7|8|7)(\d{10})',  # 89991234567
        r'\+?(\d{10,15})'  # Международные E.164 (1-15 цифр)
    ]

    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Извлекаем все цифры
            phone_digits = ''.join(filter(str.isdigit, ''.join(match)))

            # РФ номера (10-11 цифр)
            if len(phone_digits) in [10, 11] and phone_digits[:2] in ['7', '8']:
                if len(phone_digits) == 10:
                    phone_digits = '7' + phone_digits
                elif phone_digits.startswith('8'):
                    phone_digits = phone_digits.replace('8', '7', 1)

                # E.164 формат +79991234567
                normalized_phone = '+' + phone_digits
                if normalized_phone not in results['phones']['valid']:
                    results['phones']['valid'].append(normalized_phone)

            # Международные (10-15 цифр, кроме РФ)
            elif 10 <= len(phone_digits) <= 15 and not phone_digits.startswith('7'):
                normalized_phone = '+' + phone_digits[:15]  # Обрезаем до 15
                if normalized_phone not in results['phones']['valid']:
                    results['phones']['valid'].append(normalized_phone)
            else:
                invalid_phone = ''.join(match)
                if invalid_phone not in results['phones']['invalid']:
                    results['phones']['invalid'].append(invalid_phone)

    # 2. ДАТЫ: Нормализация в ISO 8601 (YYYY-MM-DD)
    date_patterns = [
        r'(\d{1,2})\.(\d{1,2})\.(\d{4})',  # DD.MM.YYYY
        r'(\d{1,2})/(\d{1,2})/(\d{4})',  # DD/MM/YYYY
        r'(\d{4})-(\d{1,2})-(\d{1,2})',  # YYYY-MM-DD
        r'(\d{4})/(\d{1,2})/(\d{1,2})',  # YYYY/MM/DD
        r'(\d{2})\.(\d{2})\.(\d{2})',  # DD.MM.YY
        r'(\d{1,2})\s*(янв|фев|мар|апр|май|июн|июл|авг|сен|окт|ноя|дек)\s*(\d{4})'  # 15 янв 2024
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
                    # DD.MM.YY -> предполагаем 20YY
                    day, month, year = int(match[0]), int(match[1]), 2000 + int(match[2])
                elif len(match) == 3 and match[2] in month_map:
                    # 15 янв 2024
                    day, month, year = int(match[0]), month_map[match[2]], int(match[-1])
                else:
                    day, month, year = map(int, match[:3])

                # Нормализация в ISO
                dt = datetime(year, month, day)
                normalized = dt.strftime('%Y-%m-%d')

                if normalized not in results['dates']['normalized']:
                    results['dates']['normalized'].append(normalized)

            except (ValueError, IndexError):
                invalid_date = '.'.join([str(x) for x in match])
                if invalid_date not in results['dates']['invalid']:
                    results['dates']['invalid'].append(invalid_date)

    # 3. ИНН: Полная проверка контрольных сумм по ГОСТ 28147-89
    inn_pattern = r'\b(\d{10}|\d{12})\b'
    raw_inns = re.findall(inn_pattern, text)

    for inn in raw_inns:
        if validate_inn(inn):
            if inn not in results['inn']['valid']:
                results['inn']['valid'].append(inn)
        else:
            if inn not in results['inn']['invalid']:
                results['inn']['invalid'].append(inn)

    # 4. КАРТЫ: Алгоритм Луна + маскировка
    card_pattern = r'\b(?:4(?:1111)?|5[1-5][0-9]{2}|2(?:22[1-9]|2[3-9][0-9]|[3-7][0-9]{2}|8[0-9]{2}|9[0-9][0-9]|81)\d{0,}|3(?:0[0-5][0-9]{2}|49[0-9]{2}|7[0-9]{2})\d{0,})\d{0,17}\b'
    raw_cards = re.findall(card_pattern, text)

    for card in raw_cards:
        digits_only = ''.join(filter(str.isdigit, card))
        if len(digits_only) in range(13, 20) and luhn_check(digits_only):
            # Маскировка: **** **** **** XXXX
            masked = '**** **** **** ' + digits_only[-4:]
            if masked not in results['cards']['valid']:
                results['cards']['valid'].append(masked)
        else:
            masked_invalid = '**** **** **** ' + digits_only[-4:] if len(digits_only) >= 4 else card
            if masked_invalid not in results['cards']['invalid']:
                results['cards']['invalid'].append(masked_invalid)

    return results


def validate_inn(inn):
    """Полная валидация ИНН по ГОСТ 28147-89"""
    if not inn.isdigit():
        return False

    if len(inn) == 10:  # Физлица/ИП
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(int(inn[i]) * weights[i] for i in range(9)) % 11 % 10
        return checksum == int(inn[9])

    elif len(inn) == 12:  # Юрлица
        # Первая контрольная цифра (11-я)
        weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum1 = sum(int(inn[i]) * weights1[i] for i in range(10)) % 11 % 10
        if checksum1 != int(inn[10]):
            return False

        # Вторая контрольная цифра (12-я)
        weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum2 = sum(int(inn[i]) * weights2[i] for i in range(11)) % 11 % 10
        return checksum2 == int(inn[11])

    return False


def luhn_check(card_number):
    """Алгоритм Луна для проверки номеров карт"""

    def digits_of(n):
        return [int(d) for d in str(n)]

    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(digits_of(i * 2) for i in odd_digits) + sum(even_digits)
    return checksum % 10 == 0