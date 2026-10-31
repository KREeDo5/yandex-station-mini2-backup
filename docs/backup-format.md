# Формат резервной копии

## Дерево

```text
backups/backup-YYYYmmdd-HHMMSS-xxxxxx/
├── images/
│   ├── mtd1.tpl.bin
│   ├── mtd2.boot.bin
│   ├── mtd3.system.bin
│   ├── mtd4.nv.bin
│   ├── mtd5.bkupgrade.bin
│   └── mtd6.recovery.bin
├── bkupgrade.tar
├── checksums.sha256
├── report.json
└── backup.log
```

Каталог создаётся эксклюзивно через `tempfile.mkdtemp` с правами `0700`. Существующие файлы не перезаписываются.

## `.part`

Каждый образ сначала пишется как:

```text
images/mtd4.nv.bin.part
```

Финальное имя создаётся только после одновременного выполнения условий:

1. SSH/`nanddump` завершился с exit code `0`.
2. Число полученных байтов точно равно ожидаемому размеру.
3. SHA-256 потока совпал с SHA-256 повторно прочитанного локального файла.
4. Финальное имя ещё не существует.

При любой ошибке `.part` остаётся. Инструмент не дополняет его `FF`, не обрезает и не переименовывает в финальное имя.

Для tar ожидаемый размер неизвестен; проверяется exit code `0`, непустой поток и SHA-256. Перед запуском `check` требует, чтобы `tar --help` показывал `-c`, `-f` и `-C`; это не является проверкой записи.

Обычная финализация использует hardlink. На файловой системе без hardlink применяется **неатомарный** fallback: финальный файл создаётся эксклюзивно, копируется, получает `fsync` и проверяется по SHA-256. При ошибке удаляется только файл, созданный текущей попыткой; `.part` сохраняется. Fallback не называется атомарной финализацией.

## `checksums.sha256`

Формат совместим с `sha256sum`:

```text
<64 hex>  images/mtd4.nv.bin
<64 hex>  bkupgrade.tar
```

Правила:

- включаются только успешно завершённые файлы;
- `report.json` не включается;
- `checksums.sha256` не включает сам себя;
- `.part` не включается;
- порядок строк сортируется по пути.

`verify` требует, чтобы каждый завершённый артефакт был перечислен, и чтобы каждая строка соответствовала завершённому артефакту.

## `report.json`

Schema version: `1.0`. Основные поля:

| Поле | Смысл |
|---|---|
| `schema_version` | Версия схемы отчёта |
| `tool` | Имя и версия инструмента |
| `generated_by_ai` | `true` |
| `started_at`, `completed_at` | UTC timestamps |
| `status` | `completed`, `failed`, `dry_run` |
| `host` | host, port, user, basename ключа; без содержимого ключа |
| `device` | uid, model, model_source, kernel, architecture, firmware_source |
| `layout` | profile_match, offsets_verified, geometry, devices, issues |
| `preflight` | локальные проверки и версия ssh |
| `checks` | результаты диагностических gate-проверок |
| `artifacts` | список образов и tar |
| `bytes_received` / `bytes_written` | получено из потока / фактически записано в `.part` |
| `stderr_tail` / `stderr_truncated` | последние байты stderr / признак усечения или ошибки чтения stderr |
| `files` | фактическое состояние `.part` и финального файла, а также признак завершённой финализации |
| `counters_exact` | `false`, если точные счётчики неизвестны после ошибки оркестратора |
| `capture` | метод, опции nanddump, ECC, OOB, отсутствие остановки Quasar/UBI |
| `consistency` | семь явных `false`-флагов |
| `consistency_notes` | текстовые ограничения |
| `warnings`, `errors` | предупреждения и ошибки |

Поля `bytes_received`, `bytes_written`, `stderr_truncated` и `files` добавлены как совместимое расширение схемы `1.0`: `verify` принимает и более старые отчёты без них. Для старых отчётов используется прежняя проверка `path`/`part_path`.

`status: completed` означает только то, что запрошенные артефакты переданы и локально проверены. Он не означает, что копия полна, согласована или пригодна для восстановления.

### Артефакт

```json
{
  "partition": "mtd4",
  "name": "nv",
  "kind": "mtd_image",
  "command": "nanddump --bb=padbad --omitoob /dev/mtd4",
  "path": "images/mtd4.nv.bin",
  "part_path": null,
  "status": "completed",
  "expected_size": 1048576,
  "actual_size": 1048576,
  "bytes_received": 1048576,
  "bytes_written": 1048576,
  "sha256": "<64 hex>",
  "exit_code": 0,
  "error": null,
  "started_at": "2026-01-01T00:00:00Z",
  "completed_at": "2026-01-01T00:02:00Z",
  "stderr_tail": "",
  "stderr_truncated": false,
  "counters_exact": true,
  "files": {
    "part": {
      "exists": false,
      "size": null,
      "kind": null,
      "path": "images/mtd4.nv.bin.part"
    },
    "final": {
      "exists": true,
      "size": 1048576,
      "kind": "file",
      "path": "images/mtd4.nv.bin",
      "sha256_verified": true,
      "created_by_this_attempt": true
    },
    "finalization_complete": true
  }
}
```

При ошибке:

- `status: failed`;
- `path: null`;
- `part_path` указывает на сохранённый `.part`;
- `error` содержит причину;
- `stderr_tail` содержит последние байты stderr (не первые), `stderr_truncated` показывает, что буфер был усечён или чтение stderr завершилось ошибкой;
- `bytes_received` — сколько байт получено из stdout, `bytes_written` — фактический размер `.part`/финального файла;
- `files` описывает оба пути независимо. Возможны состояния: только `.part`, `.part` и final, только final. Существующий final не считается проверенным, если `files.final.sha256_verified` не `true`;
- `files.final.created_by_this_attempt` может быть `true`, `false` или `"unknown"`; `"unknown"` используется при неожиданной ошибке оркестратора. Для `status: completed` `verify` требует `true`;
- `files.finalization_complete` истинно только после успешного создания final, строгого directory fsync и удаления `.part`;
- `counters_exact=false` означает, что точные `bytes_received`/`bytes_written` неизвестны после неожиданной ошибки оркестратора; состояние `files` при этом остаётся фактическим.

Разделы, которые не начали читать после более ранней ошибки, попадают в отчёт как `status: skipped` с причиной. Это не успех и не попытка чтения.

`stderr_tail` может содержать диагностический текст SSH/`nanddump`. Не публикуйте его без проверки.

## `backup.log`

Текстовый журнал с UTC timestamps. Содержит команды, статусы, размеры, SHA-256 и ошибки. Не содержит содержимого приватного ключа. Может содержать host и локальные пути — проверяйте перед публикацией.

## `verify`

`verify` не подключается к устройству и не изменяет файлы. Он:

- читает `report.json` и проверяет schema;
- отклоняет абсолютные пути, `..`, NUL и symlink-артефакты;
- проверяет размер и SHA-256 потоково;
- сообщает о `.part`;
- проверяет, что checksums не ссылаются на себя;
- открывает tar в потоковом режиме и проверяет имена и типы членов;
- не извлекает и не исполняет содержимое;
- не заявляет, что восстановление проверено.

`verify` может вернуть `failed`, если в отчёте есть failed-артефакт или оставлен `.part`. Это честный результат: такая копия неполна. Если в `files` указано, что final существует, но `sha256_verified=false`, `verify` не объявляет его проверенным.

Журнал `backup.log` ведётся по принципу best-effort: ошибки записи, flush, fsync или close не блокируют попытку сохранить failed-отчёт и не заменяют первоначальную причину ошибки. При недоступном журнале в отчёт добавляется предупреждение `logging unavailable`.

## Пример

Синтетический обезличенный пример: `examples/report.redacted.json`. Он помечен `synthetic_example: true` и не предназначен для `verify`.
