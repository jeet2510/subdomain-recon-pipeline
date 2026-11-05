.PHONY: build up down logs test

build:
	docker compose build

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

test:
	PYTHONPATH=. python3 -m pytest -q