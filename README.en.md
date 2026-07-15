# FromChat Backend — API Server

[Читать на других языках: Русский](./README.md)

<div align="center">
  <img src="https://raw.githubusercontent.com/fromchat-messenger/android/main/app/android/src/main/ic_launcher-playstore.png" width="120" alt="FromChat Logo" />
  
  **API server for FromChat messenger**
  
  [🖥️ Backend](https://github.com/fromchat-messenger/backend) • [🌐 Web Client](https://github.com/fromchat-messenger/web) • [📱 Android](https://github.com/fromchat-messenger/android) • [🌍 Website](https://github.com/fromchat-messenger/site)
</div>

---

## 📝 Description

FromChat Backend is a Python FastAPI server providing the API for all clients (Android, Web, iOS). It includes 3 microservices for message processing, file storage, and authentication.

---

## 📊 Client Comparison

| Feature | Android | Web | iOS |
|---|---|---|---|
| **Messaging & Profiles** | ✅ | ✅ | ✅ |
| **Voice/Video Calls** | ✅ | ❌ | ❌ |
| **Screen Sharing** | ✅ | ❌ | ❌ |
| **Message Reactions** | ❌ | ✅ | ❌ |
| **Rich Attachment Support** | ✅ | ❌ | ❌ |

---

## 🏗️ Architecture

Backend consists of 3 microservices deployed in Docker:

| Service | Port (dev) | Purpose |
|---|---|---|
| **Main Service** | 8300 | Public API, authentication, user profiles |
| **Messaging Service** | 8301 | Internal — encrypted message processing |
| **File Storage Service** | 8302 | Internal — file storage and uploads |

**Network Isolation:**
- `public` network: Main Service + Frontend (accessible externally)
- `services` network: all 3 services + PostgreSQL (internal only)
- PostgreSQL: only on `services` network (not public)

---

## 🏗️ Tech Stack

| Component | Version |
|---|---|
| Python | 3.12+ |
| FastAPI | latest |
| PostgreSQL | 15+ |
| SQLAlchemy | 2.0+ |
| Alembic | for DB migrations |
| Docker | 20.10+ |
| Caddy | reverse proxy |
| LiveKit | video calls |

---

## 🔒 Security

- **Message Encryption** — legal server-side encryption
- **JWT Authentication** — secure token exchange
- **HTTPS** — all requests encrypted in production
- **Rate Limiting** — DDoS protection
- **Audit Logging** — all actions tracked
- **Service Isolation** — microservices have no direct external access

---

## 📥 Self-Hosting

### Requirements

- Docker 20.10+
- Docker Compose 1.29+
- 2+ GB RAM
- 10+ GB disk space
- Python 3.12+ (local development only)

### Quick Start (Docker Compose)

**1. Clone repository:**

```bash
git clone https://github.com/fromchat-messenger/backend.git
cd backend
```

**2. Copy and fill .env file:**

```bash
cp .env.example .env
```

Edit `.env` with your parameters:

```env
# Database
POSTGRES_PASSWORD=your_secure_password_here

# API
API_HOST=0.0.0.0
API_PORT=8300
API_URL=https://api.fromchat.ru  # For production

# Firebase (optional)
FIREBASE_ENABLED=false
FIREBASE_CREDENTIALS_PATH=/path/to/firebase-cert.json

# LiveKit (optional, for calls — clients connect to host:8303 themselves)
LIVEKIT_API_KEY=your_api_key
LIVEKIT_API_SECRET=your_api_secret
```

**3. Start all services:**

```bash
docker-compose up -d
```

This starts:
- Main API Service on port 8300
- Messaging Service on port 8301 (internal)
- File Storage Service on port 8302 (internal)
- PostgreSQL database

**4. Check status:**

```bash
docker-compose ps
```

**5. View logs:**

```bash
docker-compose logs -f backend-main
```

### Database Migrations

Migrations run automatically when Docker Compose starts.

To manually run migrations:

```bash
docker-compose exec backend-main alembic upgrade head
```

### Testing the API

API is available at `http://localhost:8300` (dev) or `https://api.fromchat.ru` (prod).

**Both URL prefix variants work:**

```bash
# With /api prefix
curl http://localhost:8300/api/health

# Without prefix
curl http://localhost:8300/health
```

**Main endpoints:**

```
POST   /auth/register           — Register
POST   /auth/login              — Login
GET    /profiles/{user_id}      — User profile
GET    /messages                — Get messages
POST   /messages                — Send message
WS     /ws                      — WebSocket for real-time
POST   /calls/token             — LiveKit call token
```

### Firebase (optional)

To enable push notifications:

1. Create a Firebase project
2. Download `firebase-cert.json`
3. Set `FIREBASE_ENABLED=true` in `.env`

### Production Deployment

**With Caddy (reverse proxy):**

```bash
# Run with Caddy
docker-compose -f compose.yml -f src/docker-compose.prod.yml up -d
```

Caddy automatically:
- Routes `api.fromchat.ru` → backend:8300
- Routes `web.fromchat.ru` → web-client:8304
- Routes `fromchat.ru` → website:8301
- Updates SSL certificates (Let's Encrypt)

**Caddy Configuration (Caddyfile):**

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

### Health Check

```bash
curl http://localhost:8300/health
```

Response:
```json
{
    "status": "healthy",
    "services": {
        "database": "connected",
        "redis": "connected"
    }
}
```

### Troubleshooting

**Service won't start:**

```bash
# Check logs
docker-compose logs backend-main

# Check if port is in use
lsof -i :8300

# Restart service
docker-compose restart backend-main
```

**Database issues:**

```bash
# Check PostgreSQL status
docker-compose exec postgres psql -U fromchat -c "SELECT 1"

# Recreate database
docker-compose down -v
docker-compose up -d
```

**Migrations not applied:**

```bash
# Check migration status
docker-compose exec backend-main alembic current

# Apply migrations manually
docker-compose exec backend-main alembic upgrade head
```

---

## 🔧 Development

### Local Development (without Docker)

**Requirements:**

- Python 3.12+
- PostgreSQL 15+
- pip or poetry

**1. Create virtual environment:**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**2. Install dependencies:**

```bash
pip install -r requirements.txt
```

**3. Configure .env:**

```bash
cp .env.example .env
```

**4. Run migrations:**

```bash
alembic upgrade head
```

**5. Start server:**

```bash
python -m uvicorn backend.main:app --reload --port 8300
```

API will be available at `http://localhost:8300`

### API Documentation

Swagger UI: `http://localhost:8300/docs`

ReDoc: `http://localhost:8300/redoc`

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Create a branch for your feature
2. Submit a pull request with description
3. Ensure tests pass

```bash
# Run tests
pytest

# Check code style
flake8 backend/
```

---

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](./LICENSE) for details.

---

## 🔗 Related Repositories

- [Web Client](https://github.com/fromchat-messenger/web) — React web application
- [Android Client](https://github.com/fromchat-messenger/android) — Android application
- [Website](https://github.com/fromchat-messenger/site) — Landing & legal pages

---

## 📞 Support

- 📧 Email: support@fromchat.ru
- 💬 Telegram: https://t.me/fromchat_community
- 🐛 Issues: GitHub Issues

---

**[⬆ back to top](#fromchat-backend--api-server)**
