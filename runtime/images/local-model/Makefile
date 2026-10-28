# Static Dockerfile tests (no docker daemon). PYTHON needs PyYAML 6.0.3.
PYTHON ?= python3

.PHONY: test
test:
	"$(PYTHON)" -m unittest discover -s tests -t tests
