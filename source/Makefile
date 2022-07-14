.ONESHELL:
ENV_PREFIX=$(shell python -c "if __import__('pathlib').Path('.venv/bin/pip').exists(): print('.venv/bin/')")
USING_POETRY=$(shell grep "tool.poetry" pyproject.toml && echo "yes")

.PHONY: lock-version
lock-version: virtualenv
	@echo "Lock lambda depdency version"
	@echo ""
	@echo "Targets:"
	@$(ENV_PREFIX)python  -m pip install pip-tools
	# this lock the source depdency specified in steup.py
	pip-compile --version
	pip-compile lambda/requirements.txt
	pip-compile requirements-test.txt

.PHONY: help
help:             ## Show the help.
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@fgrep "##" Makefile | fgrep -v fgrep

.PHONY: show
show:             ## Show the current environment.
	@echo "Current environment:"
	@if [ "$(USING_POETRY)" ]; then poetry env info && exit; fi
	@echo "Running using $(ENV_PREFIX)"
	@$(ENV_PREFIX)python -V
	@$(ENV_PREFIX)python -m site

.PHONY: check-py-version
check-py-version:
	@echo "python version require to be at least 3.8.0. Leverage pyenv to set up python environment"
	$(ENV_PREFIX)python -c "import sys;exit(0) if sys.version_info.major == 3 and sys.version_info.minor >= 8  else exit(-1)"
	
	
.PHONY: install
install: virtualenv        ## Install the project in dev mode.
	@if [ "$(USING_POETRY)" ]; then poetry install && exit; fi
	@echo "Don't forget to run 'make virtualenv' if you got errors."
	$(ENV_PREFIX)pip install -r 'lambda/requirements.txt'
	$(ENV_PREFIX)pip install -r 'requirements-test.txt'
	# find ./lambda -maxdepth 1 -name "requirements*.txt" -type f -exec $(ENV_PREFIX)pip install -r '{}' ';'

.PHONY: fmt
fmt: bandit              ## Format code using black & isort.
	$(ENV_PREFIX)isort lambda/src/
	$(ENV_PREFIX)black -l 79 lambda/src/
	$(ENV_PREFIX)black -l 79 lambda/tests/

.PHONY: lint
lint: fmt         ## Run pep8, black, mypy linters.
	$(ENV_PREFIX)flake8 lambda/src/
	$(ENV_PREFIX)mypy lambda/src/  --exclude tests/  --exclude lambda/src/common/awsapi_cached_client.py

.PHONY: bandit
bandit:          ## Run pep8, black, mypy linters.
	pip install bandit
	bandit -r lambda/src

.PHONY: test
test: lint        ## Run tests and generate coverage report.
	cd lambda
	PYTHONPATH=$(PYTHONPATH):$(PWD)
	cd ..
	# remove later
	echo ENV_PREFIX= $(ENV_PREFIX)
	echo "ls pytest"
	ls -alt $(ENV_PREFIX)pytest
	echo "ls ENV_PREFIX"
	ls -alt  $(ENV_PREFIX)
	# remove end
	$(ENV_PREFIX)coverage erase
	$(ENV_PREFIX)pytest -v -s --cov-config .coveragerc --cov=lambda/src --cov=lambda/common -l --tb=short --maxfail=1 lambda/tests/ -vv
	$(ENV_PREFIX)coverage report --fail-under=80
	$(ENV_PREFIX)coverage xml -o test/coverage-reports/coverage.xml 
	sed -i -e 's/lambda\/src/source\/lambda\/src/g' test/coverage-reports/coverage.xml
	# $(ENV_PREFIX)coverage html
	# $(ENV_PREFIX)coverage lcov

.PHONY: watch
watch:            ## Run tests on every change.
	ls **/**.py | entr $(ENV_PREFIX)pytest -s -vvv -l --tb=long --maxfail=1 tests/

.PHONY: clean
clean:            ## Clean unused files.
	@rm -rf .cache
	@rm -rf .pytest_cache
	@rm -rf .mypy_cache
	@rm -rf build
	@rm -rf dist
	@rm -rf *.egg-info
	@rm -rf htmlcov
	@rm -rf .tox/
	@rm -rf docs/_build



.PHONY: virtualenv
virtualenv: check-py-version      ## Create a virtual environment.
	@if [ "$(USING_POETRY)" ]; then poetry install && exit; fi
	@echo "clean up existing virtualenv ..."
	@rm -rf .venv
	@python_verion=$(python --version)
	@echo "creating up existing virtualenv based on ${python_verion}..."
	@python -m venv .venv
	@echo active virtual environment
	@bash -c "source .venv/bin/activate"

.PHONY: release
release:          ## Create a new tag for release.
	@echo "WARNING: This operation will create s version tag and push to github"
	@read -p "Version? (provide the next x.y.z semver) : " TAG
	@echo "creating git tag : $${TAG}"
	@git tag $${TAG}
	@echo "$${TAG}" > hello_world/VERSION
	@$(ENV_PREFIX)gitchangelog > HISTORY.md
	@git add hello_world/VERSION HISTORY.md
	@git commit -m "release: version $${TAG} 🚀"
	@git push -u origin HEAD --tags
	@echo "Github Actions will detect the new tag and release the new version."