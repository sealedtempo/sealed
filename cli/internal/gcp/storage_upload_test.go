package gcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStorageUploadFileStreamsAndRetries: OS image tarballs are uploaded from disk with their exact length, and a
// 503 restarts the upload from the first byte.
func TestStorageUploadFileStreamsAndRetries(t *testing.T) {
	want := bytes.Repeat([]byte("sealed-os "), 100_000)
	path := filepath.Join(t.TempDir(), "img.tar.gz")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	c, srv := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.Method != "POST" || r.URL.Path != "/b/acme-prod-4417-sealed-boot/o" || r.URL.Query().Get("uploadType") != "media" ||
			r.URL.Query().Get("name") != "sealed-os/sealed-dstack-os-0-6-1-s1.tar.gz" || r.Header.Get("Content-Type") != "application/gzip" {
			t.Errorf("request %s %s %v", r.Method, r.URL, r.Header)
		}
		if r.ContentLength != int64(len(want)) {
			t.Errorf("content length %d, want %d", r.ContentLength, len(want))
		}
		got, _ := io.ReadAll(r.Body)
		if attempts == 1 {
			w.WriteHeader(503)
			io.WriteString(w, `{"error":{"code":503,"message":"try again","status":"UNAVAILABLE"}}`)
			return
		}
		if !bytes.Equal(got, want) {
			t.Errorf("attempt %d uploaded %d bytes, want the whole file", attempts, len(got))
		}
		io.WriteString(w, `{"name":"sealed-os/sealed-dstack-os-0-6-1-s1.tar.gz"}`)
	})
	s := &Storage{C: c, UploadRoot: srv.URL, ObjectRoot: "https://storage.googleapis.com"}
	u, err := s.UploadFile(context.Background(), "acme-prod-4417-sealed-boot", "sealed-os/sealed-dstack-os-0-6-1-s1.tar.gz", "application/gzip", path)
	if err != nil || u != "https://storage.googleapis.com/acme-prod-4417-sealed-boot/sealed-os/sealed-dstack-os-0-6-1-s1.tar.gz" || attempts != 2 {
		t.Fatalf("upload %q %v after %d attempts", u, err, attempts)
	}
	// A 403 is final, and the token never appears in the error.
	c2, srv2 := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":{"code":403,"message":"denied","status":"PERMISSION_DENIED"}}`)
	})
	_, err = (&Storage{C: c2, UploadRoot: srv2.URL}).UploadFile(context.Background(), "b", "o", "application/gzip", path)
	if !IsPermissionDenied(err) || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("403: %v", err)
	}
}
