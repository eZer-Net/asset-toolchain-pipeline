# Подробная логика IP-центричного пайплайна

## Что изменилось

Проект теперь начинает работу не с JSON-файла assets, а с домена пользователя.

На первой стадии запускается `theHarvester`, его сырой JSON сохраняется отдельно в `Results/`, затем из этого сырого отчёта строится рабочий список assets для старой IP-центричной логики.

Финальная верхнеуровневая структура отчёта сохранена:

```json
{
  "summary": {},
  "ips": [],
  "unresolved-assets": []
}
```

---

## Порядок обработки

### 1. theHarvester + standardization

Пользователь указывает домен:

```bash
python3 app.py example.com
```

Пайплайн запускает theHarvester:

```bash
uv run theHarvester -d example.com -b all -f Results/example.com-theharvester
```

Если theHarvester установлен локально в `bin/theHarvester`, запуск идёт через его окружение:

```bash
uv run theHarvester -d example.com -b all -f Results/example.com-theharvester
```

Сырой JSON сохраняется отдельно в компактном виде без служебных обёрток и дублей. В нём остаются только секции `ASNS found`, `Interesting Urls found`, `LinkedIn users found`, `IPs found`, `Emails found`, `Hosts found`, каждая с `count` и `items`:

```text
Results/example.com-theharvester.json
```

Далее пайплайн преобразует данные theHarvester:

- `hosts / subdomains / vhosts` -> `domain` или `subdomain`;
- `ips / ip / address` -> `ip`;
- `urls / links / interesting_urls / найденные http(s)-строки` -> `url`;
- `emails / people / asns` и прочая OSINT-информация остаются в сыром JSON и не используются для `cdncheck/httpx/nmap`.

После преобразования каждый asset нормализуется и, если нужно, резолвится в IP. URL в финальном отчёте не сохраняются отдельным списком IP-группы: они вкладываются в объект домена или субдомена по hostname. Если URL невозможно корректно привязать, он попадает в `unmapped-assets`.

### 2. CDNCheck

Для каждого уникального IP запускается:

```bash
cdncheck -i <ip> -j -resp -silent
```

Результат сохраняется в IP-группу:

```text
result-cdncheck
```

Если IP определён как `cdn / cloud / waf`, порт-скан по этой группе пропускается.

### 3. HTTPX

`httpx` запускается по всем `domain / subdomain / url`, которые были успешно привязаны к IP:

```bash
httpx -u https://example.com -json -probe -status-code -ip -location -fr -include-chain -silent
```

Результат сохраняется в:

```text
result-httpx
```

Если цель не отвечает:

```json
[
  {
    "status": "no-http-response"
  }
]
```

### 4. Nmap

`nmap` запускается один раз на IP-группу и только для тех IP, которые не были определены как `cdn / cloud / waf`:

```bash
nmap -Pn -n -sV -p 80,443,8080 -oX - <ip>
```

Результат сохраняется в:

```text
result-ports
```

В отчёт попадают только значимые состояния:

- `open`
- `filtered`
- `open|filtered`
- `unfiltered`

---

## API-ключи theHarvester

Часть источников theHarvester требует API-ключи. Проект умеет брать их из env и создавать `api-keys.yaml`.

Примеры:

```bash
export THEHARVESTER_SHODAN_KEY="..."
export THEHARVESTER_GITHUB_TOKEN="..."
export THEHARVESTER_HUNTER_KEY="..."
export THEHARVESTER_SECURITYTRAILS_KEY="..."
export THEHARVESTER_CENSYS_ID="..."
export THEHARVESTER_CENSYS_SECRET="..."
```

Расширяемый вариант:

```bash
export THEHARVESTER_API_KEYS_JSON='{"shodan":{"key":"..."},"censys":{"id":"...","secret":"..."}}'
```

Если env-ключи не заданы, пайплайн продолжает работу через публичные/free источники theHarvester.

---

## Практическая польза схемы

- больше не нужно вручную готовить assets JSON;
- сырой OSINT-результат theHarvester сохраняется отдельно и не теряется;
- финальная структура отчёта остаётся удобной для анализа по IP;
- порт-скан не дублируется для одного IP;
- CDN/WAF/Cloud IP можно автоматически исключать из `nmap`;
- `httpx` запускается только по целям, которые удалось связать с IP.
