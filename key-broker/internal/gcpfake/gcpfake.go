// Package gcpfake is a local stand-in for the Google APIs the key broker uses: the metadata server's token
// endpoint, Secret Manager versions:access, Cloud KMS macSign and Cloud Logging entries:write. It speaks the same
// REST shapes (including CRC32C fields) so key-broker/gcp is tested against real HTTP. Tests only.
package gcpfake

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Token is the access token the fake metadata server issues and the APIs require.
const Token = "ya29.fake-token-for-tests"

// Server is a fake of the metadata server and the three APIs on one httptest server.
type Server struct {
	*httptest.Server
	Project    string
	KeyVersion string
	MACKey     []byte

	mu       sync.Mutex
	secrets  map[string][]byte
	disabled map[string]bool
	entries  []map[string]any
	// FailNext makes the next n API calls answer 503 (retry tests).
	FailNext int
	// LoggingDown makes entries:write answer 403.
	LoggingDown bool
	// LoggingCalls counts entries:write calls; PartialSuccess records each call's partialSuccess flag.
	LoggingCalls   int
	PartialSuccess []bool
	// CorruptCRC makes Secret Manager answer a wrong dataCrc32c.
	CorruptCRC  bool
	TokenCalls  int
	SecretCalls map[string]int
	// Region is what the metadata server's instance/region answers (projects/<n>/regions/<Region>).
	Region string
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// New starts the fake. keyVersion is the KMS cryptoKeyVersion name it serves.
func New(t testing.TB, project, keyVersion string, macKey []byte) *Server {
	s := &Server{Project: project, KeyVersion: keyVersion, MACKey: macKey, secrets: map[string][]byte{}, disabled: map[string]bool{}, SecretCalls: map[string]int{},
		Region: "us-east5"}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Host is the host:port for GCE_METADATA_HOST.
func (s *Server) Host() string { return strings.TrimPrefix(s.URL, "http://") }

// SetSecret stores the latest version of a secret.
func (s *Server) SetSecret(id, val string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[id] = []byte(val)
}

// DisableSecret makes the secret's latest version disabled (FAILED_PRECONDITION).
func (s *Server) DisableSecret(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disabled[id] = true
}

// Entries returns the log entries written so far, with logName and resource folded in.
func (s *Server) Entries() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.entries...)
}

func apiError(w http.ResponseWriter, code int, status, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "status": status, "message": msg}})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/computeMetadata/v1/instance/service-accounts/default/token" {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor", http.StatusForbidden)
			return
		}
		s.TokenCalls++
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": Token, "expires_in": 3599, "token_type": "Bearer"})
		return
	}
	if r.URL.Path == "/computeMetadata/v1/instance/region" {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("projects/123456789/regions/" + s.Region))
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+Token {
		apiError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "bad token")
		return
	}
	if s.FailNext > 0 {
		s.FailNext--
		apiError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "try again")
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/projects/"+s.Project+"/secrets/") && strings.HasSuffix(r.URL.Path, "/versions/latest:access"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/projects/"+s.Project+"/secrets/"), "/versions/latest:access")
		s.SecretCalls[id]++
		v, ok := s.secrets[id]
		if !ok {
			apiError(w, http.StatusNotFound, "NOT_FOUND", fmt.Sprintf("Secret [projects/123/secrets/%s] not found or has no versions.", id))
			return
		}
		if s.disabled[id] {
			apiError(w, http.StatusBadRequest, "FAILED_PRECONDITION", "Secret Version is in DISABLED state.")
			return
		}
		crc := crc32.Checksum(v, castagnoli)
		if s.CorruptCRC {
			crc++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":    "projects/123/secrets/" + id + "/versions/3",
			"payload": map[string]any{"data": base64.StdEncoding.EncodeToString(v), "dataCrc32c": strconv.FormatUint(uint64(crc), 10)},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/"+s.KeyVersion+":macSign":
		var in struct {
			Data       string `json:"data"`
			DataCrc32c string `json:"dataCrc32c"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &in); err != nil {
			apiError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "bad json")
			return
		}
		data, err := base64.StdEncoding.DecodeString(in.Data)
		if err != nil {
			apiError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "bad data")
			return
		}
		verified := in.DataCrc32c == strconv.FormatUint(uint64(crc32.Checksum(data, castagnoli)), 10)
		if in.DataCrc32c != "" && !verified {
			apiError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "data_crc32c mismatch")
			return
		}
		h := hmac.New(sha256.New, s.MACKey)
		h.Write(data)
		mac := h.Sum(nil)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": s.KeyVersion, "mac": base64.StdEncoding.EncodeToString(mac),
			"macCrc32c": strconv.FormatUint(uint64(crc32.Checksum(mac, castagnoli)), 10), "verifiedDataCrc32c": verified,
			"protectionLevel": "HSM",
		})
	case r.Method == http.MethodPost && r.URL.Path == "/v2/entries:write":
		if s.LoggingDown {
			apiError(w, http.StatusForbidden, "PERMISSION_DENIED", "logging.logEntries.create denied")
			return
		}
		s.LoggingCalls++
		var in struct {
			LogName        string           `json:"logName"`
			Resource       map[string]any   `json:"resource"`
			Entries        []map[string]any `json:"entries"`
			PartialSuccess bool             `json:"partialSuccess"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &in); err != nil || in.LogName == "" || len(in.Entries) == 0 {
			apiError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "bad entries")
			return
		}
		s.PartialSuccess = append(s.PartialSuccess, in.PartialSuccess)
		for _, e := range in.Entries {
			e["logName"] = in.LogName
			e["resource"] = in.Resource
			s.entries = append(s.entries, e)
		}
		_, _ = w.Write([]byte("{}"))
	default:
		apiError(w, http.StatusNotFound, "NOT_FOUND", "no such method "+r.Method+" "+r.URL.Path)
	}
}
