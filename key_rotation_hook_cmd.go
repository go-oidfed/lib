package oidfed

import (
	"bytes"
	"context"
	"os/exec"
	"time"

	log "github.com/go-oidfed/lib/internal"
	"github.com/go-oidfed/lib/jwx/keymanagement/kms"
)

// CmdHookConfig configures a key rotation hook that spawns an external command
// and writes the new JWKS (as JSON) to the command's stdin. This allows
// external programs (e.g. reload scripts, HSM sync tools) to react to key
// rotations.
type CmdHookConfig struct {
	// Path is the path to the executable to run.
	Path string
	// Args are the command-line arguments passed to the executable.
	Args []string
	// Env is appended to the current process environment for the command.
	Env []string
	// Timeout is the maximum duration the command may run. Default: 30s.
	Timeout time.Duration
}

// CmdHook returns a kms.KeyRotationHook that spawns the configured command and
// writes the new JWKS JSON to its stdin. The hook always returns nil — command
// failures are logged but not propagated, so they never block or abort key
// rotation or other hooks.
func CmdHook(cfg CmdHookConfig) kms.KeyRotationHook {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return func(ctx context.Context, event kms.KeyRotationEvent) error {
		runCtx := ctx
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(runCtx, cfg.Path, cfg.Args...)
		if len(cfg.Env) > 0 {
			cmd.Env = append(cmd.Env, cfg.Env...)
		}

		stdin, err := cmd.StdinPipe()
		if err != nil {
			log.Logger().Error().Err(err).
				Str("entity_id", event.EntityID).
				Str("cmd", cfg.Path).
				Msg("key rotation cmd hook: could not create stdin pipe")
			return nil
		}

		jwksBytes, mErr := event.NewJWKS.MarshalJSON()
		if mErr != nil {
			log.Logger().Error().Err(mErr).
				Str("entity_id", event.EntityID).
				Str("cmd", cfg.Path).
				Msg("key rotation cmd hook: could not marshal JWKS")
			_ = cmd.Wait()
			return nil
		}

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err = cmd.Start(); err != nil {
			log.Logger().Error().Err(err).
				Str("entity_id", event.EntityID).
				Str("cmd", cfg.Path).
				Msg("key rotation cmd hook: could not start command")
			return nil
		}

		if _, wErr := stdin.Write(jwksBytes); wErr != nil {
			log.Logger().Error().Err(wErr).
				Str("entity_id", event.EntityID).
				Str("cmd", cfg.Path).
				Msg("key rotation cmd hook: could not write to stdin")
		}
		_ = stdin.Close()

		if wErr := cmd.Wait(); wErr != nil {
			log.Logger().Error().Err(wErr).
				Str("entity_id", event.EntityID).
				Str("cmd", cfg.Path).
				Str("stdout", stdout.String()).
				Str("stderr", stderr.String()).
				Msg("key rotation cmd hook: command failed")
			return nil
		}

		log.Logger().Info().
			Str("entity_id", event.EntityID).
			Str("cmd", cfg.Path).
			Strs("added_kids", event.AddedKIDs).
			Msg("key rotation cmd hook: command completed")
		return nil
	}
}
