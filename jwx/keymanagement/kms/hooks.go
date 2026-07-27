package kms

import (
	"context"

	log "github.com/go-oidfed/lib/internal"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
)

// KeyRotationEvent carries the information about a key rotation or seeding
// event to registered KeyRotationHook callbacks.
type KeyRotationEvent struct {
	// EntityID is the entity identifier of the entity whose keys were rotated,
	// sourced from KMSConfig.EntityID. May be empty if not configured.
	EntityID string
	// NewJWKS is the full set of valid (non-expired, non-revoked) public keys
	// after the rotation, i.e. what the entity publishes in its Entity
	// Configuration. This includes keys announced for future use (nbf in the
	// future).
	NewJWKS jwx.JWKS
	// AddedKIDs are the kids of the newly generated keys.
	AddedKIDs []string
	// RotatedKIDs are the kids of the old keys that were replaced by this
	// rotation. Empty for seeding (initial generation, scheduled future keys).
	RotatedKIDs []string
	// Revoked indicates whether the rotated keys were revoked (emergency
	// revocation) as opposed to a routine rotation.
	Revoked bool
	// Reason is the revocation reason, if any.
	Reason string
}

// KeyRotationHook is a callback invoked after a signing key was generated or
// rotated by the KMS. Hooks are executed in separate goroutines; errors and
// panics are logged and never propagated to the caller, so a failing hook
// never blocks or aborts key rotation or other hooks.
type KeyRotationHook func(ctx context.Context, event KeyRotationEvent) error

// fireKeyRotationHooks builds a KeyRotationEvent from the current PublicKeyStorage
// state and dispatches it to all registered hooks concurrently. Each hook runs
// in its own goroutine with panic recovery; errors are logged. This function
// returns immediately after launching the goroutines.
func fireKeyRotationHooks(
	hooks []KeyRotationHook,
	entityID string,
	pkStorage public.PublicKeyStorage,
	addedKIDs, rotatedKIDs []string,
	revoked bool,
	reason string,
) {
	if len(hooks) == 0 {
		return
	}

	valid, err := pkStorage.GetValid()
	if err != nil {
		log.Logger().Error().Err(err).Str("entity_id", entityID).
			Msg("KMS: key rotation hooks: failed to get valid public keys for event")
		return
	}
	newJWKS, err := valid.JWKS()
	if err != nil {
		log.Logger().Error().Err(err).Str("entity_id", entityID).
			Msg("KMS: key rotation hooks: failed to build JWKS for event")
		return
	}

	event := KeyRotationEvent{
		EntityID:    entityID,
		NewJWKS:     newJWKS,
		AddedKIDs:   addedKIDs,
		RotatedKIDs: rotatedKIDs,
		Revoked:     revoked,
		Reason:      reason,
	}

	for _, hook := range hooks {
		go func(h KeyRotationHook) {
			defer func() {
				if r := recover(); r != nil {
					log.Logger().Error().
						Interface("panic", r).
						Str("entity_id", event.EntityID).
						Strs("added_kids", event.AddedKIDs).
						Msg("KMS: key rotation hook panicked")
				}
			}()
			if err := h(context.Background(), event); err != nil {
				log.Logger().Error().Err(err).
					Str("entity_id", event.EntityID).
					Strs("added_kids", event.AddedKIDs).
					Msg("KMS: key rotation hook failed")
			}
		}(hook)
	}
}
