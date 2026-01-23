.PHONY: scan api ui dev validate

scan:
	python -m secpatchlab.cli scan

api:
	uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

ui:
	cd frontend && npm install && npm run dev -- --host

dev:
	$(MAKE) -j 2 api ui

validate:
	python -m secpatchlab.cli validate --package $(PKG) $(if $(PATCH),--patch $(PATCH),)
