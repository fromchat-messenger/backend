# Серверная часть FromChat

[Read in other languages: English](./README.en.md)

_Написано ИИ. Могут быть ошибки._

## 📝 Описание

Python/FastAPI бэкенд для клиентов FromChat (Android, Web, iOS). Несколько сервисов в Docker: публичный API, контейнер для обработки сообщений, файлы, LiveKit, PostgreSQL. Для продакшена два дополнительных микросервиса — Caddy + HAProxy (`compose.prod.yml`).

## 📊 Сравнение клиентов

| Возможность | Android | Веб | iOS |
|---|---|---|---|
| **Обмен сообщениями и профили** | ✅ | ✅ | ❌ |
| **Голосовые/видеозвонки** | ✅ | ✅ | ❌ |
| **Демонстрация экрана** | ✅ | ✅ | ❌ |
| **Реакции на сообщения** | ❌ | ✅ | ❌ |
| **Расширенная поддержка вложений** | ✅ | ❌ | ❌ |

## 🏗️ Архитектура

| Сервис | Порт (dev) | Сеть | Назначение |
|---|---|---|---|
| **backend** (main) | 8300 | public + services | Публичный API, auth, профили, WebSocket |
| **messaging** | 8301 | services | Внутренний — сообщения |
| **file_storage** | 8302 | services | Внутренний — файлы |
| **livekit** | 8303 / 8304 (+ UDP) | public | Звонки |
| **postgres** | 127.0.0.1:5432 | services | БД |
| **caddy** + **haproxy** | 80/443 (prod) | — | TLS / reverse proxy (`compose.prod.yml`) |

- `public` — доступ снаружи (main, livekit, …)
- `services` — только внутри стека (messaging, file_storage, postgres)

## 🔧 Стек

| Компонент | Версия / роль |
|---|---|
| Python | 3.12+ |
| FastAPI | API |
| PostgreSQL | БД (отдельные БД/пользователи на сервис) |
| SQLAlchemy 2 + Alembic | ORM и миграции |
| Docker Compose | оркестрация |
| LiveKit | звонки |
| Caddy + HAProxy | продакшен |

## 🔒 Безопасность

- Легальное серверное шифрование сообщений + compliance keys
- JWT
- HTTPS в production
- Rate limiting (slowapi)
- Messaging / file storage не публикуются наружу
- Firebase / Web Push (VAPID) — опционально

## 📥 Запуск

### Требования

- Docker 20.10+ и Compose plugin (с поддержкой `watch`)
- Python 3.12+ только для `scripts/generate-env.sh` (ключи VAPID / compliance)
- ~2 GB RAM, ~10 GB диск

### 1. Клонировать

```bash
git clone https://github.com/fromchat-messenger/backend.git
cd backend
```

### 2. Сгенерировать `.env`

Файла `.env.example` нет — переменные создаёт генератор:

```bash
bash scripts/generate-env.sh
```

Типичные ключи: `JWT_SECRET`, `COMPLIANCE_PUBLIC_KEY`, пароли Postgres (`POSTGRES_PASSWORD`, `MAIN_DB_PASSWORD`, …), `LIVEKIT_*`, `MESSAGE_RETENTION_DAYS`, VAPID, опционально `RELEASES_TOKEN` / Firebase. Фильтр чата включён по умолчанию (`CHAT_FILTER_URL` в compose; `ENABLE_CHAT_FILTER=0` чтобы выключить).

Также пишется `compliance_keypair.txt` — **приватный ключ храните офлайн**.

### 3. Поднять стек (разработка)

```bash
bash scripts/dev.sh
# то же самое:
docker compose --env-file .env -f compose.yml up --build --watch
```

Остановить:

```bash
docker compose --env-file .env -f compose.yml down --remove-orphans
```

### 4. Проверка

```bash
curl http://localhost:8300/health
# {"status":"healthy","service":"main"}
```

Swagger: `http://localhost:8300/docs`  
ReDoc: `http://localhost:8300/redoc`

### Admin CLI (локально)

Интерактивная консоль владельца (смена режима шифрования — только user id `1`). Зависимости: `httpx`, `rich` из `requirements.txt`:

```bash
bash scripts/admin-cli
./scripts/admin-cli -c encryption-mode
./scripts/admin-cli --server http://127.0.0.1:8300
```

По умолчанию `https://api.fromchat.ru` (`--server` или `FC_ADMIN_API_URL`). В сессии: `server <url>` — проверка как в приложении. Команды: `server`, `encryption-mode`, `set-encryption-mode compliance|e2ee`, `toggle-encryption-mode`, `compliance-mode on|off`.

Клиентский web в dev проксирует backend как `/api` → сюда на `:8300`.

### Production edge

```bash
docker compose --env-file .env -f compose.yml -f compose.prod.yml up -d
```

Обычный one-click / опубликованный стек — репозиторий [deployment](https://github.com/fromchat-messenger/deployment).

### Firebase (опционально)

Положите `firebase-cert.json` в корень репозитория (compose монтирует его в контейнер main).

## 🛠 Устранение неполадок

```bash
docker compose --env-file .env -f compose.yml logs -f backend
docker compose --env-file .env -f compose.yml ps
lsof -i :8300
```

Проблемы с БД:

```bash
docker compose --env-file .env -f compose.yml exec postgres \
  psql -U postgres -c "SELECT 1"
# полный сброс данных (осторожно):
docker compose --env-file .env -f compose.yml down -v
```

## 🤝 Внесение вклада

1. Ветка под изменение
2. PR с описанием
3. Проверьте, что стек поднимается (`bash scripts/dev.sh`) и `/health` отвечает

## 📄 Лицензия

Проект распространяется на условиях GNU Affero General Public License v3.0 (как и остальные репозитории FromChat).

## 🔗 Связанные репозитории

- [Web Client](https://github.com/fromchat-messenger/web)
- [Android Client](https://github.com/fromchat-messenger/android)
- [Website](https://github.com/fromchat-messenger/site)
- [Deployment](https://github.com/fromchat-messenger/deployment)
- [Updater](https://github.com/fromchat-messenger/updater)

## 📞 Поддержка

- 💬 Telegram: https://t.me/fromchat_community
- 🐛 Issues: GitHub Issues соответствующего репозитория