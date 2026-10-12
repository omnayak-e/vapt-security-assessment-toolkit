.PHONY: install test
install:
	python -m pip install -r requirements.txt
test:
	python -m pip install pytest
	pytest -q
