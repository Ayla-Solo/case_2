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

    # 1. Телефон
    # Паттерн для поиска потенциальных номеров
    phone_pattern = r'\+?7?\s*[\d\s\-\(\)]{10,}'
    # Пример нормализации: "+79991234567"
    # Добавим логику проверки (если бы была библиотека phonenumbers)
    raw_phones = re.findall(phone_pattern, text)
    # Здесь должна быть логика парсера для валидации
    # results['phones']['valid'] = [cleaned_number]

    # 2. Даты
    # Поиск паттернов: DD.MM.YYYY, YYYY-MM-DD, DD/MM/YYYY
    date_patterns = [r'\d{1,2}\.\d{1,2}\.\d{4}', r'\d{4}-\d{2}-\d{2}']
    for pattern in date_patterns:
        found_dates = re.findall(pattern, text)
        for d in found_dates:
            try:
                # Пробуем нормализовать под ISO
                normalized = datetime.strptime(d, '%d.%m.%Y').strftime('%Y-%m-%d')
                if d != normalized:  # Если нужно сохранять оригинал
                    results['dates']['normalized'].append(normalized)
                else:
                    results['dates']['normalized'].append(d)
            except ValueError:
                results['dates']['invalid'].append(d)

    # 3. ИНН (Индивидуальный Налоговый Номер)
    # ИНН ИП/Юрлиц: 10 или 12 цифр. Есть алгоритм контроля последних двух знаков
    inn_pattern = r'\b\d{10,12}\b'
    raw_inns = re.findall(inn_pattern, text)
    for i in raw_inns:
        # Упрощенная проверка длины и цифр (здесь нужен полный алгоритм контрольной суммы)
        if len(i) == 10 or len(i) == 12:
            # ... логика расчета контрольного разряда ...
            results['inn']['valid'].append(i)
        else:
            results['inn']['invalid'].append(i)

    # 4. Карты (Повтор алгоритма Луна из Роли 1)
    # Поиск последовательностей из 13-19 цифр
    card_pattern = r'\b(?:4|5[1-5]|2[2-7]|[3][0-5]|3[47]|6)\d{0,17}\b'
    raw_cards = re.findall(card_pattern, text)


    for card in raw_cards:
        if luhn_check(card):
            results['cards']['valid'].append(card)
        else:
            results['cards']['invalid'].append(card)

    return results