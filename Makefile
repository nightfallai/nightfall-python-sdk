.PHONY: help clean dev docs serve-docs package test

help:
	@echo "This project assumes that an active Python virtualenv is present."
	@echo "The following make targets are available:"
	@echo "	dev 	install all deps for dev env"
	@echo "	docs	create pydocs for all relveant modules"
	@echo "	serve-docs	serve generated documentation locally"
	@echo "	test	run all tests with coverage"

clean:
	rm -rf dist/*

dev:
	pip install -r dev-requirements.txt
	pip install -e .

docs:
	$(MAKE) -C docsrc html
	@cp -a docsrc/_build/html/. docs

serve-docs:
	python3 -m http.server --directory docs

package:
	python -m build --sdist --wheel --outdir dist/

test:
	coverage run -m unittest discover
	coverage html
