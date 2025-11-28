# Yet another Whatsminer CLI

> Dual-language README (English & Russian)  
> Version: Whatsminer API v3.0.1  
> ⚠️ Do not use docs/code from v2.5.. — protocol is **incompatible**.

---

## 🇬🇧 English

### Overview
`whatsminercli` lets you execute any command from **Whatsminer API v3.0.1**.
It automatically generates `ts` + `token` for `set.*`, fetches `salt` when needed, and encrypts parameters for sensitive commands.
The package also exposes a small Python API so you can call miners from your own scripts.

- CLI flags for parameters (mutually exclusive):
  - `--param VALUE` → scalar value (int/float/bool/string)
  - `--param-json JSON` → structured parameter (object/array)
  - `--param-file FILE.json` → parameter from JSON file

### Installation
Python 3.8+
```bash
# Install from the repository root
pip install .  # or: pip install -e . for editable mode

# Default AES backend
pip install pycryptodome
# Alternative backend
pip install pycryptodomex
```

### Config (`miner-conf.json`)
```json
{
  "host": "192.168.1.2",
  "port": 4433,
  "login": "super",
  "password": "passw0rd"
}
```

### CLI Usage
```bash
whatsminercli [--config miner-conf.json] <subcommand> [options]
# or
python -m whatsminer_cli [--config miner-conf.json] <subcommand> [options]
```

### Library usage
```python
from whatsminer_cli import call_whatsminer, DEFAULT_PORT

response = call_whatsminer(
    host="192.168.1.2",
    port=DEFAULT_PORT,
    account="super",
    account_password="passw0rd",
    cmd="get.device.info",
    param="miner",
)
print(response)
```

#### Subcommands
| Command | Description |
|--------|-------------|
| `get-salt` | Retrieve salt via `get.device.info` |
| `call` | Execute any API command |

---

## Examples

> For `set.*` commands the tool will auto-fetch `salt` if not provided.

### Get miner salt
```bash
whatsminercli --config miner-conf.json get-salt
```

### Get device info
```bash
whatsminercli --config miner-conf.json call get.device.info --param miner
```

### Miner power controls

#### set.miner.power (absolute, Watts)
```bash
whatsminercli --config miner-conf.json call set.miner.power --param 3200
# or: --param-json '{"power":3200}'
```

#### set.miner.power_limit (Watts)
```bash
whatsminercli --config miner-conf.json call set.miner.power_limit --param 3300
# or: --param-json '{"limit":3300}'
```

#### set.miner.power_mode (0=Normal, 1=LowPower, 2=Sleep)
```bash
whatsminercli --config miner-conf.json call set.miner.power_mode --param 1
# or: --param-json '{"mode":1}'
```

#### set.miner.power_percent (0–100%)
```bash
whatsminercli --config miner-conf.json call set.miner.power_percent --param 85
# or: --param-json '{"percent":85}'
```

### Thermal / fans

#### set.miner.fan_speed (0=auto, otherwise fixed RPM)
```bash
whatsminercli --config miner-conf.json call set.miner.fan_speed --param 4800
# or: --param-json '{"fan":4800}'
```

#### set.miner.fan_auto (toggle if supported by firmware)
```bash
whatsminercli --config miner-conf.json call set.miner.fan_auto --param true
# or: --param-json '{"auto":true}'
```

### Frequency / performance

#### set.miner.freq (MHz)
```bash
whatsminercli --config miner-conf.json call set.miner.freq --param 580
# or: --param-json '{"freq":580}'
```

#### set.miner.boost (example enable/disable)
```bash
whatsminercli --config miner-conf.json call set.miner.boost --param false
# or: --param-json '{"enable":false}'
```

### Pools / Credentials (encrypted)

#### set.miner.pools (encrypted, use file or JSON)
```bash
whatsminercli --config miner-conf.json call set.miner.pools --param-file pools.json
```
`pools.json`:
```json
{
  "pools": [
    { "url": "stratum+tcp://pool1.example.com:3333", "user": "wallet.worker1", "pass": "x" },
    { "url": "stratum+tcp://pool2.example.com:3333", "user": "wallet.worker2", "pass": "x" }
  ]
}
```

#### set.user.change_passwd (encrypted)
```bash
whatsminercli --config miner-conf.json call set.user.change_passwd --param-json '{"old_pass":"passw0rd","new_pass":"new123"}'
```

### System

#### set.system.reboot
```bash
whatsminercli --config miner-conf.json call set.system.reboot
```

#### ⚠️ set.system.update_firmware — not implemented
Firmware update requires binary upload and chunked transfer. This CLI **does not** implement it.

---

## Typical responses

### Success
```json
{ "STATUS": "S", "Msg": { "ok": true } }
```

### Error
```json
{ "STATUS": "E", "Msg": "Invalid token or salt" }
```

---

## 🇷🇺 Русская версия


### Обзор
`whatsminercli` выполняет команды API Whatsminer v3.0.1.
Для `set.*` автоматически вычисляются `ts` и `token`, при необходимости утилита получает `salt`, а параметры некоторых команд шифрует AES-ECB.

- флаги параметров (взаимоисключающие):
  - `--param VALUE` → скаляр (int/float/bool/строка)
  - `--param-json JSON` → структурированный параметр (объект/массив)
  - `--param-file FILE.json` → параметр из JSON-файла

### Примеры

#### Получить salt
```bash
whatsminercli --config miner-conf.json get-salt
```

#### Информация о устройстве
```bash
whatsminercli --config miner-conf.json call get.device.info --param miner
```

#### Управление мощностью
```bash
# Абсолютная мощность (Вт)
whatsminercli --config miner-conf.json call set.miner.power --param 3200

# Лимит мощности (Вт)
whatsminercli --config miner-conf.json call set.miner.power_limit --param 3300

# Режим мощности (0=Нормальный, 1=Энергосбережение, 2=Сон)
whatsminercli --config miner-conf.json call set.miner.power_mode --param 1

# Процент мощности (0–100%)
whatsminercli --config miner-conf.json call set.miner.power_percent --param 85
```

#### Терморежим / Вентиляторы
```bash
whatsminercli --config miner-conf.json call set.miner.fan_speed --param 4800
```

#### Частота (МГц)
```bash
whatsminercli --config miner-conf.json call set.miner.freq --param 580
```

#### Перезагрузка
```bash
whatsminercli --config miner-conf.json call set.system.reboot
```

#### Пулы (шифрование)
```bash
whatsminercli --config miner-conf.json call set.miner.pools --param-file pools.json
```

`pools.json`:
```json
{
  "pools": [
    { "url": "stratum+tcp://pool1.example.com:3333", "user": "wallet.worker1", "pass": "x" },
    { "url": "stratum+tcp://pool2.example.com:3333", "user": "wallet.worker2", "pass": "x" }
  ]
}
```

#### Смена пароля (шифрование)
```bash
whatsminercli --config miner-conf.json call set.user.change_passwd --param-json '{"old_pass":"passw0rd","new_pass":"new123"}'
```

### ⚠️ Обновление прошивки
`set.system.update_firmware` не реализовано в данной версии CLI, т.к. требует передачи бинарного файла по частям.

---

**Note:** Only for Whatsminer API **v3.0.1**. Version 2.5 is **incompatible**.
