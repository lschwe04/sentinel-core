package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestServeAgentArtifactProvidesChecksum(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "sentinel-agent")
	content := []byte("agent-binary")
	if err := os.WriteFile(artifact, content, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_LINUX_BINARY", artifact)

	req := httptest.NewRequest(http.MethodGet, "/downloads/linux/sentinel-agent", nil)
	res := httptest.NewRecorder()
	ServeAgentArtifact("linux").ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	hash := sha256.Sum256(content)
	if got, want := res.Header().Get("X-Checksum-SHA256"), hex.EncodeToString(hash[:]); got != want {
		t.Fatalf("checksum mismatch: got %q, want %q", got, want)
	}
}

func TestServeAgentArtifactRejectsUnknownKind(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/downloads/unknown", nil)
	res := httptest.NewRecorder()
	ServeAgentArtifact("unknown").ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.Code)
	}
}
