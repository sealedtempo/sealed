# Static Dockerfile tests (no docker daemon; PYTHON needs PyYAML 6.0.3) and the gate's Go tests.
PYTHON ?= python3
GO ?= go

.PHONY: test
test:
	"$(PYTHON)" -m unittest discover -s tests -t tests
	cd gate && "$(GO)" vet . && "$(GO)" test -count=1 .
