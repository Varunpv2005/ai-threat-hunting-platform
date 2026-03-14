# =============================================================================
# Makefile — SOC Platform developer shortcuts
# =============================================================================

DC      := docker compose
BACKEND := soc_backend
PGUSER  ?= socuser
PGDB    ?= socdb

.PHONY: help up down dev elk logs logs-api ps \
        build rebuild clean clean-vols \
        test shell-api shell-db seed \
        simulate health

# ── Default ───────────────────────────────────────────────────────────────────
help:
	@printf "\n  \033[1mSOC Platform — commands\033[0m\n\n"
	@printf "  \033[36mup\033[0m              Build + start (postgres redis backend frontend)\n"
	@printf "  \033[36mdev\033[0m             Hot-reload backend + Vite frontend (dev profile)\n"
	@printf "  \033[36melk\033[0m             Add Elasticsearch + Kibana\n"
	@printf "  \033[36mdown\033[0m            Stop all containers\n"
	@printf "  \033[36mlogs\033[0m            Tail all logs\n"
	@printf "  \033[36mlogs-api\033[0m        Tail backend logs only\n"
	@printf "  \033[36mps\033[0m              Container status\n"
	@printf "  \033[36mbuild\033[0m           Build images\n"
	@printf "  \033[36mrebuild\033[0m         Build images (no cache)\n"
	@printf "  \033[36mclean\033[0m           Remove containers + images\n"
	@printf "  \033[36mclean-vols\033[0m      Remove named volumes (DESTRUCTIVE)\n"
	@printf "  \033[36mtest\033[0m            Run test suite inside backend container\n"
	@printf "  \033[36mshell-api\033[0m       Bash shell in backend container\n"
	@printf "  \033[36mshell-db\033[0m        psql shell in postgres container\n"
	@printf "  \033[36msimulate\033[0m        Fire a test brute-force simulation\n"
	@printf "  \033[36mhealth\033[0m          Check all service health endpoints\n\n"

# ── Lifecycle ─────────────────────────────────────────────────────────────────
up:
	@[ -f .env ] || (echo "Copying .env.example → .env"; cp .env.example .env)
	$(DC) up -d --build --remove-orphans
	@printf "\n  Dashboard  → \033[36mhttp://localhost:3000\033[0m\n"
	@printf "  API docs   → \033[36mhttp://localhost:8000/docs\033[0m\n\n"

down:
	$(DC) --profile elk --profile dev down

dev:
	@[ -f .env ] || cp .env.example .env
	$(DC) up -d postgres redis
	$(DC) --profile dev up --build backend-dev

elk:
	@[ -f .env ] || cp .env.example .env
	$(DC) --profile elk up -d --build --remove-orphans
	@printf "\n  Kibana → \033[36mhttp://localhost:5601\033[0m\n\n"

# ── Logs / status ─────────────────────────────────────────────────────────────
logs:
	$(DC) logs -f --tail=100

logs-api:
	$(DC) logs -f --tail=100 backend

ps:
	$(DC) ps

# ── Build ─────────────────────────────────────────────────────────────────────
build:
	$(DC) build --parallel

rebuild:
	$(DC) build --no-cache --parallel

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	$(DC) --profile elk --profile dev down --remove-orphans
	docker image rm -f soc_backend soc_frontend 2>/dev/null || true

clean-vols:
	@printf "\033[31m⚠ This removes all SOC data volumes!\033[0m\n"
	@read -p "Type 'yes' to confirm: " c; [ "$$c" = "yes" ] || exit 1
	$(DC) --profile elk --profile dev down -v --remove-orphans

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	$(DC) exec $(BACKEND) python backend/tests/test_api.py

# ── Shells ────────────────────────────────────────────────────────────────────
shell-api:
	$(DC) exec $(BACKEND) bash

shell-db:
	$(DC) exec soc_postgres psql -U $(PGUSER) -d $(PGDB)

# ── Seed / simulate ───────────────────────────────────────────────────────────
seed:
	$(DC) exec $(BACKEND) python -c "\
	  import sys; sys.path.insert(0,'.'); \
	  from backend.api.store import store; \
	  store.bootstrap(n_train=1000); \
	  print('Seeded', len(store._logs), 'logs')"

simulate:
	curl -s -X POST http://localhost:8000/api/v1/simulate_attack \
	  -H "Content-Type: application/json" \
	  -d '{"attack_type":"brute_force","geo_country":"RU","intensity":"high"}' \
	  | python3 -m json.tool

# ── Health ────────────────────────────────────────────────────────────────────
health:
	@curl -sf http://localhost:8000/     && printf "  \033[32m✓\033[0m Backend\n"  || printf "  \033[31m✗\033[0m Backend\n"
	@curl -sf http://localhost:3000/     && printf "  \033[32m✓\033[0m Frontend\n" || printf "  \033[31m✗\033[0m Frontend\n"
	@$(DC) exec soc_postgres pg_isready -U $(PGUSER) -d $(PGDB) -q \
	  && printf "  \033[32m✓\033[0m Postgres\n" || printf "  \033[31m✗\033[0m Postgres\n"
	@$(DC) exec soc_redis redis-cli -a $${REDIS_PASSWORD:-redispass} ping -q \
	  && printf "  \033[32m✓\033[0m Redis\n"    || printf "  \033[31m✗\033[0m Redis\n"
