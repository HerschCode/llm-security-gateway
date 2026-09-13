.PHONY: test evaluate evaluate-full docker-build docker-up

test:
	python -m pytest tests/ -v

# Reads committed comparison_table.md -- no torch or API keys needed.
# To re-run against the full 120-case corpus: make evaluate-full  (requires full requirements.txt)
evaluate:
	mkdir -p reports
	python scripts/report_security_eval.py

evaluate-full:
	python scripts/evaluate.py

docker-build:
	docker build -t llm-security-gateway .

docker-up:
	docker compose up --build
