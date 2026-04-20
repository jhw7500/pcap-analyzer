.PHONY: test test-all test-e2e cov cov-html fetch-vendor

VENDOR_DIR := static/vendor
TAILWIND_URL := https://cdn.tailwindcss.com
PLOTLY_URL := https://cdn.plot.ly/plotly-2.32.0.min.js

fetch-vendor:
	@mkdir -p $(VENDOR_DIR)
	@echo "[*] Tailwind runtime 다운로드..."
	@curl -fsSL -o $(VENDOR_DIR)/tailwind.js $(TAILWIND_URL)
	@echo "[*] Plotly.js 다운로드..."
	@curl -fsSL -o $(VENDOR_DIR)/plotly.min.js $(PLOTLY_URL)
	@echo "완료. 설정 페이지에서 '오프라인 에셋 사용'을 체크하세요."


test:
	python3 -m pytest tests/ -v

test-all:
	python3 -m pytest tests/ -v -m ""

test-e2e:
	python3 -m pytest tests/ -v -m e2e

cov:
	python3 -m pytest tests/ --cov=analyzer --cov=ai --cov=routes --cov=config --cov-report=term-missing

cov-html:
	python3 -m pytest tests/ --cov=analyzer --cov=ai --cov=routes --cov=config --cov-report=html
	@echo "Coverage report: htmlcov/index.html"
