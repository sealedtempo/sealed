# Unit and packaging tests. PYTHON needs PyYAML 6.0.3 and (optional) jsonschema 4.25.1.
PYTHON ?= python3

.PHONY: test fragment
test:
	"$(PYTHON)" tools/build_fragment.py --check
	"$(PYTHON)" -m unittest discover -s tests -t tests

fragment:
	"$(PYTHON)" tools/build_fragment.py
