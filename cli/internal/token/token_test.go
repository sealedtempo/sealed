package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func sample() Connection {
	return Connection{
		V:               Version,
		Project:         "acme-prod-4417",
		Region:          "us-central1",
		DeployerAccount: "sealed-deployer@acme-prod-4417.iam.gserviceaccount.com",
		KeyBrokerURL:    "https://sealed-key-broker-abc123-uc.a.run.app",
		Customer:        "0x00000000000000000000000000000000000000C1",
		Subnetwork:      "sealed-subnet",
		IssuedAt:        1761600000,
	}
}

func TestRoundTrip(t *testing.T) {
	tok, err := Encode(sample())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "sct_") || strings.ContainsAny(tok[4:], "+/=") {
		t.Fatalf("token %q is not sct_ + unpadded base64url", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok[4:])
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@acme-prod-4417.iam.gserviceaccount.com","keyBrokerUrl":"https://sealed-key-broker-abc123-uc.a.run.app","customer":"0x00000000000000000000000000000000000000c1","subnetwork":"sealed-subnet","issuedAt":1761600000}`
	if string(raw) != want {
		t.Fatalf("payload\n got %s\nwant %s", raw, want)
	}
	c, err := Decode("  " + tok + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Customer != "0x00000000000000000000000000000000000000c1" || c.Project != "acme-prod-4417" || c.KeyBrokerURL != "https://sealed-key-broker-abc123-uc.a.run.app" {
		t.Fatalf("decoded %+v", c)
	}
	// Padded base64url (some tools add it) is accepted.
	padded := "sct_" + base64.URLEncoding.EncodeToString(raw)
	if _, err := Decode(padded); err != nil {
		t.Fatalf("padded token: %v", err)
	}
}

func TestRejects(t *testing.T) {
	enc := func(s string) string { return "sct_" + base64.RawURLEncoding.EncodeToString([]byte(s)) }
	good, _ := Encode(sample())
	cases := map[string]string{
		"prefix":        "sk_" + good[4:],
		"not base64":    "sct_!!!",
		"not json":      enc("hello"),
		"unknown field": enc(`{"v":1,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@acme-prod-4417.iam.gserviceaccount.com","keyBrokerUrl":"https://kb.example.com","customer":"0x00000000000000000000000000000000000000c1","privateKey":"x"}`),
		"trailing":      enc(`{"v":1} {}`),
		"version":       enc(`{"v":2,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@acme-prod-4417.iam.gserviceaccount.com","keyBrokerUrl":"https://kb.example.com","customer":"0x00000000000000000000000000000000000000c1"}`),
		"other project": enc(`{"v":1,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@evil-proj-0001.iam.gserviceaccount.com","keyBrokerUrl":"https://kb.example.com","customer":"0x00000000000000000000000000000000000000c1"}`),
		"http broker":   enc(`{"v":1,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@acme-prod-4417.iam.gserviceaccount.com","keyBrokerUrl":"http://kb.example.com","customer":"0x00000000000000000000000000000000000000c1"}`),
		"broker path":   enc(`{"v":1,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@acme-prod-4417.iam.gserviceaccount.com","keyBrokerUrl":"https://kb.example.com/x","customer":"0x00000000000000000000000000000000000000c1"}`),
		"broker creds":  enc(`{"v":1,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@acme-prod-4417.iam.gserviceaccount.com","keyBrokerUrl":"https://u:p@kb.example.com","customer":"0x00000000000000000000000000000000000000c1"}`),
		"mixed case":    enc(`{"v":1,"project":"acme-prod-4417","region":"us-central1","deployerAccount":"sealed-deployer@acme-prod-4417.iam.gserviceaccount.com","keyBrokerUrl":"https://kb.example.com","customer":"0x00000000000000000000000000000000000000C1"}`),
		"too long":      "sct_" + strings.Repeat("A", MaxLen),
	}
	for name, tok := range cases {
		if _, err := Decode(tok); err == nil {
			t.Errorf("%s: accepted %q", name, tok)
		}
	}
	bad := sample()
	bad.Region = "Central"
	if _, err := Encode(bad); err == nil {
		t.Error("Encode accepted a bad region")
	}
}
