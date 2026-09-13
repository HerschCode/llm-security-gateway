.PHONY: test evaluate evaluate-full external-benchmark docker-build docker-up

test:
	python -m pytest tests/ -v

# Reads committed comparison_table.md + p3_external_benchmark.json -- no torch or API keys needed.
# To re-run against the full 120-case corpus: make evaluate-full  (requires full requirements.txt)
evaluate:
	mkdir -p reports
	python scripts/report_security_eval.py

evaluate-full:
	python scripts/evaluate.py

# OOD benchmark against jailbreak_llms (Shen et al. 2023), n=150 sample
external-benchmark:
	mkdir -p reports
	python scripts/external_benchmark.py

docker-build:
	docker build -t llm-security-gateway .

docker-up:
	docker compose up --build
