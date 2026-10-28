# Docker fixtures

Stand-in apps for `TestComposeUpWithDocker` (`docker_test.go`). Every service runs busybox (pinned by digest in the test), whose `httpd` answers the probes; the composed stack keeps every network, address, `dns`, proxy variable, capability, `sysctls`, `security_opt`, config and the envexec ready gate as composed. `llm-gateway` here is a stand-in, so the stack also gets sealed-mpp-payer, sealed-verifierd and the verifier network. None of these are catalog entries.
