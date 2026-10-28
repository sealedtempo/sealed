# Unit and packaging tests. PYTHON needs PyYAML 6.0.3, httpx 0.28.1 and (optional) jsonschema 4.25.1.
PYTHON ?= python3

.PHONY: test
test:
	"$(PYTHON)" -m unittest discover -s tests -t tests
