# Сервисная структура проекта

## Цель

Разделить пайплайн на отдельные зоны ответственности:

- ввод домена и портов;
- проверка/установка инструментов;
- запуск theHarvester;
- преобразование raw OSINT-результата в assets;
- IP-центричная обработка через `cdncheck -> httpx -> nmap`;
- сохранение финального отчёта.

Финальная верхнеуровневая структура JSON-отчёта сохранена:

```json
{
  "summary": {},
  "ips": [],
  "unresolved-assets": []
}
```

---

## 1. Input Service

Файл:

```text
src/asset_pipeline/services/input_service.py
```

Зона ответственности:

- принять домен пользователя;
- нормализовать домен, если передан URL;
- провалидировать формат домена;
- провалидировать список портов;
- нормализовать assets, которые пришли после преобразования raw-отчёта theHarvester;
- выделить `scan_host`;
- привязать asset к `target_ip` через DNS resolve;
- посчитать статистику входа.

CLI entrypoint:

```text
services/input_service/main.py
```

Пример:

```bash
python3 services/input_service/main.py --domain example.com --ports 80,443
```

---

## 2. Tool Service

Файл:

```text
src/asset_pipeline/services/tool_service.py
```

Зона ответственности:

- показать каталог обязательных инструментов;
- найти локальные/системные инструменты;
- установить отсутствующие инструменты;
- скачать/подготовить `theHarvester` в `bin/theHarvester`;
- подготовить Python-окружение theHarvester через `uv sync` или `.venv`;
- собрать `api-keys.yaml` из env-переменных;
- вернуть реальные пути для исполнения.

Обязательные инструменты:

```text
theHarvester
httpx
cdncheck
nmap
```

CLI entrypoint:

```text
services/tool_service/main.py
```

---

## 3. Orchestrator Service

Файл:

```text
src/asset_pipeline/services/orchestrator_service.py
```

Зона ответственности:

- запустить theHarvester по домену;
- сохранить сырой JSON theHarvester в `Results/`;
- преобразовать raw JSON в assets для стандартной IP-центричной логики;
- построить начальный отчёт;
- запустить `cdncheck` по IP-группам;
- запустить `httpx` по резолвящимся web-целям;
- запустить `nmap` по не-CDN IP;
- сохранять промежуточные состояния отчёта;
- собрать финальный `summary`;
- поддерживать текущий блочный консольный UX.

CLI entrypoint:

```text
services/orchestrator_service/main.py
```

Пример:

```bash
python3 services/orchestrator_service/main.py example.com
```

---

## 4. Shared layer

Файл:

```text
src/asset_pipeline/shared.py
```

Вынесено в общий слой:

- dataclass-модели;
- общие константы;
- путь к `Results/`;
- путь к `bin/`;
- путь к `bin/theHarvester`;
- progress rendering;
- блочный консольный вывод;
- запуск внешних команд;
- обработка graceful stop;
- helper-функции установки бинарников из GitHub releases.

---

## Совместимость

### Сохранено

- IP-центричный финальный отчёт;
- блоки `summary`, `ips`, `unresolved-assets`;
- логика `cdncheck -> httpx -> nmap`;
- redirect tracking для `httpx`;
- 500ms rate-limit на запуск новых `httpx` задач;
- пропуск `nmap`, если IP определён как CDN/WAF/Cloud.

### Изменено

- вместо пути к JSON-файлу теперь передаётся домен;
- первая стадия сама запускает theHarvester;
- сырой JSON theHarvester сохраняется отдельно;
- assets для дальнейших стадий строятся автоматически из raw JSON theHarvester.

### Добавлено

- установка `theHarvester` в `bin/theHarvester`;
- подготовка `.venv`/`uv` окружения для theHarvester;
- env-интеграция для API-ключей theHarvester;
- summary-поля `theharvester-*`.
