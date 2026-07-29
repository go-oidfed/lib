package kms

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-oidfed/lib/jwx"
	"github.com/go-oidfed/lib/jwx/keymanagement/public"
	"github.com/go-oidfed/lib/unixtime"
)

func TestFireKeyRotationHooks_NoHooks(t *testing.T) {
	pks := newMemPKStorage(time.Now())
	// Should be a no-op with no panic.
	fireKeyRotationHooks(nil, "https://entity.example", pks, []string{"k1"}, nil, false, "")
}

func TestFireKeyRotationHooks_DispatchesEvent(t *testing.T) {
	now := time.Now()
	pks := newMemPKStorage(now)

	// Add a key to storage so NewJWKS is non-empty.
	sk, pkJWK, kid, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)
	_ = sk
	pke := public.PublicKeyEntry{
		KID:       kid,
		Key:       public.JWKKey{Key: pkJWK},
		IssuedAt:  &unixtime.Unixtime{Time: now},
		NotBefore: &unixtime.Unixtime{Time: now},
	}
	require.NoError(t, pks.Add(pke))

	var (
		gotEvent KeyRotationEvent
		wg       sync.WaitGroup
	)
	wg.Add(1)

	hook := func(_ context.Context, event KeyRotationEvent) error {
		gotEvent = event
		wg.Done()
		return nil
	}

	fireKeyRotationHooks(
		[]KeyRotationHook{hook},
		"https://entity.example",
		pks,
		[]string{kid},
		[]string{"oldKid"},
		true,
		"compromised",
	)

	wg.Wait()

	assert.Equal(t, "https://entity.example", gotEvent.EntityID)
	assert.Equal(t, []string{kid}, gotEvent.AddedKIDs)
	assert.Equal(t, []string{"oldKid"}, gotEvent.RotatedKIDs)
	assert.True(t, gotEvent.Revoked)
	assert.Equal(t, "compromised", gotEvent.Reason)
	assert.NotNil(t, gotEvent.NewJWKS.Set)
	assert.Equal(t, 1, gotEvent.NewJWKS.Len())
}

func TestFireKeyRotationHooks_PanicRecovered(t *testing.T) {
	now := time.Now()
	pks := newMemPKStorage(now)
	sk, pkJWK, kid, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)
	_ = sk
	pke := public.PublicKeyEntry{
		KID:       kid,
		Key:       public.JWKKey{Key: pkJWK},
		IssuedAt:  &unixtime.Unixtime{Time: now},
		NotBefore: &unixtime.Unixtime{Time: now},
	}
	require.NoError(t, pks.Add(pke))

	var (
		gotEvent     KeyRotationEvent
		wg           sync.WaitGroup
		panicHookRan bool
	)
	wg.Add(2)

	panicHook := func(_ context.Context, _ KeyRotationEvent) error {
		defer wg.Done()
		panic("boom")
	}
	normalHook := func(_ context.Context, event KeyRotationEvent) error {
		defer wg.Done()
		gotEvent = event
		panicHookRan = true
		return nil
	}

	// The panicking hook is registered first; the normal hook must still run.
	fireKeyRotationHooks(
		[]KeyRotationHook{panicHook, normalHook},
		"https://entity.example",
		pks,
		[]string{kid},
		nil,
		false, "",
	)

	wg.Wait()
	assert.True(t, panicHookRan, "second hook should run despite first hook panicking")
	assert.Equal(t, []string{kid}, gotEvent.AddedKIDs)
}

func TestFireKeyRotationHooks_ErrorLoggedNotPropagated(t *testing.T) {
	now := time.Now()
	pks := newMemPKStorage(now)
	sk, pkJWK, kid, err := jwx.GenerateKeyPair(jwa.RS256(), 2048)
	require.NoError(t, err)
	_ = sk
	pke := public.PublicKeyEntry{
		KID:       kid,
		Key:       public.JWKKey{Key: pkJWK},
		IssuedAt:  &unixtime.Unixtime{Time: now},
		NotBefore: &unixtime.Unixtime{Time: now},
	}
	require.NoError(t, pks.Add(pke))

	var wg sync.WaitGroup
	wg.Add(2)

	errHook := func(_ context.Context, _ KeyRotationEvent) error {
		defer wg.Done()
		return errors.New("hook error")
	}
	okHook := func(_ context.Context, _ KeyRotationEvent) error {
		defer wg.Done()
		return nil
	}

	// Must not panic and must return (both hooks launched).
	fireKeyRotationHooks(
		[]KeyRotationHook{errHook, okHook},
		"https://entity.example",
		pks,
		[]string{kid},
		nil,
		false, "",
	)
	wg.Wait()
}
