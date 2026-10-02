"""Editable domain list with comment headings; metadata never becomes a match."""


def parse(text):
    from policy import domain_pattern
    if not isinstance(text, str) or len(text) > 100_000:
        raise ValueError('Список доменов: не более 100 000 символов')
    groups = [{'title': '', 'domains': []}]
    lines = []; domains = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            lines.append(''); continue
        if line.startswith('#'):
            title = line[1:].strip()
            if not title or len(title) > 160:
                raise ValueError(f'Строка {number}: заголовок после # — от 1 до 160 символов')
            groups.append({'title': title, 'domains': []})
            lines.append('# ' + title); continue
        try:kind, name = domain_pattern(line)
        except ValueError as error:
            raise ValueError(f'Строка {number}: {error}') from error
        value = ('*.' if kind == 'subdomains' else '') + name
        lines.append(value); domains.append(value); groups[-1]['domains'].append(value)
    if len(domains) > 4096 or len(groups) > 129:
        raise ValueError('Не более 4096 доменных условий и 128 заголовков в правиле')
    return {'text': '\n'.join(lines).strip(), 'domains': domains,
            'groups': [g for g in groups if g['title'] or g['domains']]}


def text_for(profile):
    return profile.get('domain_document', '\n'.join(profile.get('domains', [])))


def validate(profile):
    if 'domain_document' not in profile:
        return
    parsed = parse(profile['domain_document'])
    if parsed['domains'] != profile.get('domains', []):
        raise ValueError('Доменные условия не совпадают с текстом списка: откройте правило и сохраните его заново')
