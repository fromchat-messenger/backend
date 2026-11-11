# Docker on Cloud Agent VMs

Docker 27+ programs bridge networks with **iptables-nft**, but many base images still
ship **iptables-legacy** with `FORWARD` policy `DROP`. Container-to-container traffic on
custom bridges then times out (Postgres, messaging, file_storage unreachable from `backend`).

**Fix:** run `scripts/ensure-docker-forwarding.sh` once per boot before `docker compose up`.

```bash
./scripts/ensure-docker-forwarding.sh
docker compose up -d
```
