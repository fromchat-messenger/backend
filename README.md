# FromChat Backend — API сервер

[Read in other languages: English](./README.en.md)

<div align="center">
  <img src="https://raw.githubusercontent.com/fromchat-messenger/android/main/app/android/src/main/ic_launcher-playstore.png" width="120" alt="FromChat Logo" />
  
  **API сервер для FromChat мессенджера**
  
  [🖥️ Backend](https://github.com/fromchat-messenger/backend) • [🌐 Веб-клиент](https://github.com/fromchat-messenger/web) • [📱 Android](https://github.com/fromchat-messenger/android) • [🌍 Website](https://github.com/fromchat-messenger/site)
</div>

---

## 📝 Описание

Backend для FromChat — это Python FastAPI сервер, обеспечивающий API для всех клиентов (Android, Web, iOS). Включает 3 микросервиса для обработки сообщений, файлов и аутентификации.

---

## 📊 Сравнение клиентов

| Возможность | Android | Веб | iOS |
|---|---|---|---|
| **Обмен сообщениями и профили** | ✅ | ✅ | ✅ |
| **Голосовые/видеозвонки** | ✅ | ❌ | ❌ |
| **Совместное использование экрана** | ✅ | ❌ | ❌ |
| **Реакции на сообщения** | ❌ | ✅ | ❌ |
| **Расширенная поддержка вложений** | ✅ | ❌ | ❌ |

---

## 🏗️ Архитектура

Backend состоит из 3 микросервисов, развёрнутых в Docker:

| Сервис | Порт (дев) | Назначение |
|---|---|---|
| **Main Service** | 8300 | Публичный API, аутентификация, профили пользователей |
| **Messaging Service** | 8301 | Внутренний — обработка зашифрованных сообщений |
| **File Storage Service** | 8302 | Внутренний — хранилище и загрузка файлов |

**Сетевая изоляция:**
- `public` сеть: Main Service + Frontend (доступна извне)
- `services` сеть: все 3 сервиса + PostgreSQL (только внутри)
- PostgreSQL: только на `services` сети (не публичная)

---

## 🔧 Технологический стек

| Компонент | Версия |
|---|---|
| Python | 3.12+ |
| FastAPI | последняя |
| PostgreSQL | 15+ |
| SQLAlchemy | 2.0+ |
| Alembic | для миграций БД |
| Docker | 20.10+ |
| Caddy | обратный прокси |
| LiveKit | видеозвонки |

---

## 🔒 Безопасность

- **Шифрование сообщений** — легальное серверное шифрование
- **JWT-аутентификация** — безопасный обмен токенами
- **HTTPS** — все запросы в production шифруются
- **Ограничение скорости** — защита от DDoS
- **Аудит логирования** — отслеживание всех действий
- **Изоляция сервисов** — микросервисы не имеют прямого доступа извне

---

## 📥 Самостоятельное размещение

### Требования

- Docker 20.10+
- Docker Compose 1.29+
- 2+ GB ОЗУ
- 10+ GB дискового пространства
- Python 3.12+ (только для локальной разработки)

### Быстрый старт (Docker Compose)

**1. Клонировать репозиторий:**

```bash
git clone https://github.com/fromchat-messenger/backend.git
cd backend
```

**2. Скопировать и заполнить .env файл:**

```bash
cp .env.example .env
```

Отредактируйте `.env` с вашими параметрами:

```env
# Database
POSTGRES_PASSWORD=your_secure_password_here

# API
API_HOST=0.0.0.0
API_PORT=8300
API_URL=https://api.fromchat.ru  # Для production

# Firebase (опционально)
FIREBASE_ENABLED=false
FIREBASE_CREDENTIALS_PATH=/path/to/firebase-cert.json

# LiveKit (optional, for calls — clients connect to host:8303 themselves)
LIVEKIT_API_KEY=your_api_key
LIVEKIT_API_SECRET=your_api_secret
```

**3. Запустить все сервисы:**

```bash
docker-compose up -d
```

Это запустит:
- Main API Service на порту 8300
- Messaging Service на порту 8301 (внутреннее)
- File Storage Service на порту 8302 (внутреннее)
- PostgreSQL базу данных

**4. Проверить статус:**

```bash
docker-compose ps
```

**5. Просмотреть логи:**

```bash
docker-compose logs -f backend-main
```

### Миграции базы данных

Миграции выполняются автоматически при запуске Docker Compose.

Для ручного выполнения миграций:

```bash
docker-compose exec backend-main alembic upgrade head
```

### Проверка API

API доступен на `http://localhost:8300` (dev) или `https://api.fromchat.ru` (prod).

**Оба варианта префикса URL работают:**

```bash
# С префиксом /api
curl http://localhost:8300/api/health

# Без префикса
curl http://localhost:8300/health
```

**Основные endpoints:**

```
POST   /auth/register           — Регистрация
POST   /auth/login              — Вход
GET    /profiles/{user_id}      — Профиль пользователя
GET    /messages                — Получить сообщения
POST   /messages                — Отправить сообщение
WS     /ws                      — WebSocket для реал-тайма
POST   /calls/token             — Токен для LiveKit вызова
```

### Firebase (опционально)

Для включения push-уведомлений:

1. Создайте проект Firebase
2. Загрузите `firebase-cert.json`
3. Установите `FIREBASE_ENABLED=true` в `.env`

### Production развертывание

**С Caddy (обратный прокси):**

```bash
# Запустить с Caddy
docker-compose -f compose.yml -f src/docker-compose.prod.yml up -d
```

Caddy автоматически:
- Маршрутизирует `api.fromchat.ru` → backend:8300
- Маршрутизирует `web.fromchat.ru` → web-client:8304
- Маршрутизирует `fromchat.ru` → website:8301
- Обновляет SSL сертификаты (Let's Encrypt)

**Конфигурация Caddy (Caddyfile):**

```caddy
api.fromchat.ru {
    reverse_proxy localhost:8300
    encode gzip
}

web.fromchat.ru {
    reverse_proxy localhost:8304
    encode gzip
}

fromchat.ru {
    reverse_proxy localhost:8301
    encode gzip
}
```

### Проверка здоровья

```bash
curl http://localhost:8300/health
```

Ответ:
```json
{
    "status": "healthy",
    "services": {
        "database": "connected",
        "redis": "connected"
    }
}
```

### Устранение неполадок

**Сервис не запускается:**

```bash
# Проверить логи
docker-compose logs backend-main

# Проверить, не занят ли порт
lsof -i :8300

# Перестартить сервис
docker-compose restart backend-main
```

**Проблема с БД:**

```bash
# Проверить статус PostgreSQL
docker-compose exec postgres psql -U fromchat -c "SELECT 1"

# Пересоздать БД
docker-compose down -v
docker-compose up -d
```

**Миграции не применились:**

```bash
# Проверить статус миграций
docker-compose exec backend-main alembic current

# Применить миграции вручную
docker-compose exec backend-main alembic upgrade head
```

---

## 🔧 Разработка

### Локальная разработка (без Docker)

**Требования:**

- Python 3.12+
- PostgreSQL 15+
- pip или poetry

**1. Создать виртуальное окружение:**

```bash
python -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate
```

**2. Установить зависимости:**

```bash
pip install -r requirements.txt
```

**3. Настроить .env:**

```bash
cp .env.example .env
```

**4. Запустить миграции:**

```bash
alembic upgrade head
```

**5. Запустить сервер:**

```bash
python -m uvicorn backend.main:app --reload --port 8300
```

API будет доступен на `http://localhost:8300`

### API документация

Swagger UI: `http://localhost:8300/docs`

ReDoc: `http://localhost:8300/redoc`

---

## 🤝 Внесение вклада

Приветствуются внесение вклада! Пожалуйста:

1. Создайте ветку для вашей функции
2. Отправьте пулл-реквест с описанием
3. Убедитесь, что тесты проходят

```bash
# Запустить тесты
pytest

# Проверить код стиль
flake8 backend/
```

---

## 📄 Лицензия

Этот проект лицензирован в соответствии с лицензией GNU Affero General Public License v3.0. Подробности см. в файле [LICENSE](./LICENSE).

---

## 🔗 Связанные репозитории

- [Web Client](https://github.com/fromchat-messenger/web) — React веб-приложение
- [Android Client](https://github.com/fromchat-messenger/android) — Android приложение
- [Website](https://github.com/fromchat-messenger/site) — Лендинг и юридические страницы

---

## 📞 Поддержка

- 📧 Email: support@fromchat.ru
- 💬 Telegram: https://t.me/fromchat_community
- 🐛 Issues: GitHub Issues

---

**[⬆ вернуться к началу](#fromchat-backend--api-сервер)**
