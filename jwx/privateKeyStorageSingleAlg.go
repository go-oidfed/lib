package jwx

import (
	"crypto"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/go-oidfed/lib/internal"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"
	"github.com/zachmann/go-utils/fileutils"

	"github.com/go-oidfed/lib/unixtime"
)

type privateKeyStorageSingleAlg struct {
	typeID    string
	signer    crypto.Signer
	alg       jwa.SignatureAlgorithm
	keyDir    string
	rsaKeyLen int
	rollover  RolloverConf
}

func (sks privateKeyStorageSingleAlg) keyFilePath(future bool) string {
	var f string
	if future {
		f = "f"
	}
	return fmt.Sprintf("%s/%s_%s%s.pem", sks.keyDir, sks.typeID, sks.alg.String(), f)
}

// GetDefault returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (sks privateKeyStorageSingleAlg) GetDefault() (crypto.Signer, jwa.SignatureAlgorithm) {
	return sks.signer, sks.alg
}

// GetForAlgs takes a list of acceptable signature algorithms and returns a
// usable crypto.Signer or nil as well as the corresponding
// jwa.SignatureAlgorithm
func (sks privateKeyStorageSingleAlg) GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	if slices.Contains(algs, sks.alg.String()) {
		return sks.GetDefault()
	}
	return nil, jwa.SignatureAlgorithm{}

}

func (sks *privateKeyStorageSingleAlg) initKeyRotation(pks *pkCollection, pksOnChange func() error) {
	if !sks.rollover.Enabled {
		return
	}
	go func() {
		for {
			sleepDuration := time.Until(pks.jwks[0].MinimalExpirationTime().Time.Add(-5 * time.Second))
			if sleepDuration > 0 {
				time.Sleep(sleepDuration)
			}
			if err := sks.GenerateNewKeys(pks, pksOnChange); err != nil {
				internal.Error(err)
			}
		}
	}()
}

// Load loads the key from disk or generates a new one if the key does not exist on disk
func (sks *privateKeyStorageSingleAlg) Load(pks *pkCollection, pksOnChange func() error) error {
	signer, err := readSignerFromFile(sks.keyFilePath(false), sks.alg)
	if err != nil {
		internal.Warn(err)
		if err = sks.GenerateNewKeys(pks, pksOnChange); err != nil {
			return err
		}
		sks.initKeyRotation(pks, pksOnChange)
		return nil
	}
	sks.signer = signer

	if len(pks.jwks) == 0 {
		// This is only for the case that there is no keys.jwks yet,
		// but there was a private key file.
		set := NewJWKS()
		pk, err := signerToPublicJWK(
			signer, sks.alg, keyLifetimeConf{
				NowIssued: false,
				Expires:   sks.rollover.Enabled,
				Lifetime:  sks.rollover.Interval.Duration(),
			},
		)
		if err != nil {
			return err
		}
		if err = set.AddKey(pk); err != nil {
			return errors.WithStack(err)
		}
		pks.jwks = []JWKS{set}
		if err = pksOnChange(); err != nil {
			return err
		}
	}

	if !fileutils.FileExists(sks.keyFilePath(true)) {
		_, err = generateStoreAndSetNextPrivateKey(
			pks, sks.alg, sks.rsaKeyLen, keyLifetimeConf{
				Expires:  sks.rollover.Enabled,
				Lifetime: sks.rollover.Interval.Duration(),
				Nbf:      &unixtime.Unixtime{Time: pks.jwks[0].MinimalExpirationTime().Add(-10 * time.Second)},
			}, sks.keyFilePath(true), true,
		)
		if err != nil {
			return err
		}
		if err = pksOnChange(); err != nil {
			return err
		}
	}

	sks.initKeyRotation(pks, pksOnChange)
	return nil
}

// GenerateNewKeys generates a new key
func (sks *privateKeyStorageSingleAlg) GenerateNewKeys(pks *pkCollection, pksOnChange func() error) error {
	skNext, err := readSignerFromFile(sks.keyFilePath(true), sks.alg)
	if err != nil {
		skNext, err = generateStoreAndSetNextPrivateKey(
			pks, sks.alg, sks.rsaKeyLen, keyLifetimeConf{
				Expires:  sks.rollover.Enabled,
				Lifetime: sks.rollover.Interval.Duration(),
			}, sks.keyFilePath(true), true,
		)
		if err != nil {
			return err
		}
	}

	sks.signer = skNext
	if err = errors.WithStack(os.Rename(sks.keyFilePath(true), sks.keyFilePath(false))); err != nil {
		return err
	}

	newKeys := NewJWKS()
	sk, pk, err := generateKeyPair(
		sks.alg, sks.rsaKeyLen, keyLifetimeConf{
			Expires:  sks.rollover.Enabled,
			Lifetime: sks.rollover.Interval.Duration(),
			Nbf:      &unixtime.Unixtime{Time: pks.jwks[1].MinimalExpirationTime().Add(-10 * time.Second)},
		},
	)
	if err != nil {
		return err
	}
	if err = writeSignerToFile(sk, sks.keyFilePath(true)); err != nil {
		return err
	}
	if err = newKeys.AddKey(pk); err != nil {
		return errors.WithStack(err)
	}
	pks.rotate(newKeys)
	return pksOnChange()
}
