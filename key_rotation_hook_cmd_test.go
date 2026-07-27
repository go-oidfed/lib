package oidfed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
)

func TestCmdHook_WritesJWKSToStdin(t *testing.T) {
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "jwks_received.json")

	jwks := createTestJWKS(t, "test-kid")

	hook := CmdHook(CmdHookConfig{
		Path:    "sh",
		Args:    []string{"-c", "cat > " + outputFile},
		Timeout: 10 * time.Second,
	})

	event := kms.KeyRotationEvent{
		EntityID:  "https://entity.example",
		NewJWKS:   *jwks,
		AddedKIDs: []string{"test-kid"},
	}

	err := hook(context.Background(), event)
	require.NoError(t, err)

	// Give the goroutine a moment to finish (hook runs in a goroutine via
	// fireKeyRotationHooks, but here we call it directly and it's synchronous
	// up to cmd.Wait).
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.NotEmpty(t, data, "output file should contain JWKS JSON")
	assert.Contains(t, string(data), "test-kid")
}

func TestCmdHook_FailingCommandDoesNotError(t *testing.T) {
	hook := CmdHook(CmdHookConfig{
		Path:    "sh",
		Args:    []string{"-c", "exit 1"},
		Timeout: 5 * time.Second,
	})

	event := kms.KeyRotationEvent{
		EntityID:  "https://entity.example",
		NewJWKS:   *createTestJWKS(t, "k1"),
		AddedKIDs: []string{"k1"},
	}

	// The hook logs the failure but returns nil.
	err := hook(context.Background(), event)
	assert.NoError(t, err)
}

func TestCmdHook_NonexistentCommandDoesNotError(t *testing.T) {
	hook := CmdHook(CmdHookConfig{
		Path:    "/nonexistent/command/that/does/not/exist",
		Timeout: 5 * time.Second,
	})

	event := kms.KeyRotationEvent{
		EntityID:  "https://entity.example",
		NewJWKS:   *createTestJWKS(t, "k1"),
		AddedKIDs: []string{"k1"},
	}

	err := hook(context.Background(), event)
	assert.NoError(t, err)
}
