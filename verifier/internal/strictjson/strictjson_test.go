package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

type inner struct {
	ID string `json:"id"`
}

type doc struct {
	Customer string            `json:"customer"`
	Apps     []inner           `json:"apps"`
	Nested   *inner            `json:"nested,omitempty"`
	Raw      json.RawMessage   `json:"raw"`
	Env      map[string]string `json:"env"`
	Untagged string
	Skipped  string `json:"-"`
	Embedded
}

type Embedded struct {
	Salt string `json:"salt"`
}

func TestUnmarshalAcceptsCanonicalSpelling(t *testing.T) {
	var d doc
	raw := `{"customer":"a","apps":[{"id":"crm","extra":{"ID":1}}],"nested":{"id":"x"},"raw":{"Customer":1,"customer":2},` +
		`"env":{"ID":"1","Id2":"2"},"Untagged":"u","salt":"s","unknown":{"x":1}}`
	err := Unmarshal([]byte(raw), &d)
	if err == nil || !strings.Contains(err.Error(), `$.raw`) {
		t.Fatalf("collision inside a raw message must still be refused: %v", err)
	}
	raw = strings.Replace(raw, `"Customer":1,`, ``, 1)
	if err := Unmarshal([]byte(raw), &d); err != nil {
		t.Fatal(err)
	}
	if d.Customer != "a" || d.Apps[0].ID != "crm" || d.Nested.ID != "x" || d.Untagged != "u" || d.Salt != "s" || d.Env["ID"] != "1" {
		t.Fatalf("%+v", d)
	}
}

func TestUnmarshalRejectsAmbiguousKeys(t *testing.T) {
	for name, raw := range map[string]string{
		"case variant of a field":     `{"Customer":"b"}`,
		"both spellings":              `{"customer":"a","CUSTOMER":"b"}`,
		"exact duplicate":             `{"customer":"a","customer":"b"}`,
		"unicode fold (long s)":       `{"\u017falt":"b"}`,
		"nested struct field":         `{"apps":[{"ID":"crm"}]}`,
		"pointer struct field":        `{"nested":{"Id":"x"}}`,
		"embedded field":              `{"SALT":"s"}`,
		"untagged field by case":      `{"untagged":"u"}`,
		"duplicate in unknown object": `{"unknown":{"a":1,"A":2}}`,
		"duplicate in map":            `{"env":{"K":"1","k":"2"}}`,
		"escaped duplicate":           `{"customer":"a","\u0063ustomer":"b"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var d doc
			if err := Unmarshal([]byte(raw), &d); err == nil {
				t.Fatalf("accepted %s as %+v", raw, d)
			}
		})
	}
	var evs []inner
	if err := Unmarshal([]byte(`[{"id":"a"},{"Id":"b"}]`), &evs); err == nil {
		t.Fatal("slice element with a case variant accepted")
	}
	if err := Unmarshal([]byte(`{"id":"a"} {"id":"b"}`), &inner{}); err == nil {
		t.Fatal("trailing value accepted")
	}
	if err := Unmarshal([]byte(`{"id":`), &inner{}); err == nil {
		t.Fatal("truncated JSON accepted")
	}
}

func TestFoldKey(t *testing.T) {
	if foldKey("Kelvin") != foldKey("\u212aelvin") || foldKey("salt") != foldKey("\u017falt") {
		t.Fatal("fold classes")
	}
	if foldKey("customer") == foldKey("customers") {
		t.Fatal("distinct keys folded together")
	}
}
