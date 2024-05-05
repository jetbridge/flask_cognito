SHELL := /bin/bash

env-install:
	pipenv --python 3.12
	pipenv install --dev

env-update:
	pipenv lock

test:
	pipenv run python -m unittest discover .
