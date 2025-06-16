.PHONY: test lint install clean

install:
	pip install -r requirements.txt

test:
	tox

lint:
	ruff check

clean:
	rm -rf __pycache__ .pytest_cache .tox