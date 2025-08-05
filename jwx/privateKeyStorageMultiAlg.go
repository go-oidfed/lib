package jwx

import (
	"crypto"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/fileutils"

	"github.com/go-oidfed/lib/unixtime"
)

type privateKeyStorageMultiAlg struct {
	typeID     string
	signers    map[jwa.SignatureAlgorithm]crypto.Signer
	algs       []jwa.SignatureAlgorithm
	defaultAlg jwa.SignatureAlgorithm
	keyDir     string
	rsaKeyLen  int
	rollover   RolloverConf
}

func (sks privateKeyStorageMultiAlg) keyFilePath(alg jwa.SignatureAlgorithm, future bool) string {
	var f string
	if future {
		f = "f"
	}
	return fmt.Sprintf("%s/%s_%s%s.pem", sks.keyDir, sks.typeID, alg.String(), f)
}

// GetDefault returns a crypto.Signer and the corresponding jwa.SignatureAlgorithm
func (sks privateKeyStorageMultiAlg) GetDefault() (crypto.Signer, jwa.SignatureAlgorithm) {
	if len(sks.algs) == 0 {
		return nil, jwa.SignatureAlgorithm{}
	}
	defaultAlg := sks.defaultAlg
	if defaultAlg.String() == "" {
		defaultAlg = sks.algs[0]
	}
	return sks.signers[defaultAlg], defaultAlg
}

// GetForAlgs takes a list of acceptable signature algorithms and returns a
// usable crypto.Signer or nil as well as the corresponding
// jwa.SignatureAlgorithm
func (sks privateKeyStorageMultiAlg) GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	for _, alg := range sks.algs {
		if slices.Contains(algs, alg.String()) {
			return sks.signers[alg], alg
		}
	}
	return nil, jwa.SignatureAlgorithm{}
}

func (sks *privateKeyStorageMultiAlg) initKeyRotation(pks *pkCollection, pksOnChange func() error) {
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
				log.Error(err)
			}
		}
	}()
}

// Load loads the private keys from disk and if necessary generates missing keys
func (sks *privateKeyStorageMultiAlg) Load(pks *pkCollection, pksOnChange func() error) error {
	addPublicKeysToJWKS := false
	if sks.signers == nil {
		sks.signers = make(map[jwa.SignatureAlgorithm]crypto.Signer)
	}
	if len(pks.jwks) == 0 {
		pks.jwks = []JWKS{NewJWKS()}
		addPublicKeysToJWKS = true
	}
	pksChanged := false

	for _, alg := range sks.algs {
		signer, changed, err := sks.loadOrGenerateSigner(alg, pks, addPublicKeysToJWKS)
		if err != nil {
			return err
		}
		pksChanged = pksChanged || changed
		sks.signers[alg] = signer

		// Ensure the next key file exists for rollover
		if !fileutils.FileExists(sks.keyFilePath(alg, true)) {
			_, err = generateStoreAndSetNextPrivateKey(
				pks, alg, sks.rsaKeyLen, keyLifetimeConf{
					Expires:  sks.rollover.Enabled,
					Lifetime: sks.rollover.Interval.Duration(),
					Nbf:      &unixtime.Unixtime{Time: pks.jwks[0].MinimalExpirationTime().Add(-10 * time.Second)},
				}, sks.keyFilePath(alg, true), false,
			)
			pksChanged = true
			if err != nil {
				return err
			}
		}
	}

	if addPublicKeysToJWKS || pksChanged {
		if err := pksOnChange(); err != nil {
			return err
		}
	}
	sks.initKeyRotation(pks, pksOnChange)
	return nil
}

// loadOrGenerateSigner loads a signer from disk or generates a new one if it doesn't exist.
// If addPublicKeysToJWKS is true, it also adds the public key to the pkCollection.
func (sks *privateKeyStorageMultiAlg) loadOrGenerateSigner(
	alg jwa.SignatureAlgorithm, pks *pkCollection, addPublicKeysToJWKS bool,
) (crypto.Signer, bool, error) {
	filePath := sks.keyFilePath(alg, false)
	signer, err := readSignerFromFile(filePath, alg)
	if err != nil {
		// Could not load key, generating a new one for this alg
		sk, pk, err := generateKeyPair(
			alg,
			sks.rsaKeyLen,
			keyLifetimeConf{
				NowIssued: true,
				Expires:   sks.rollover.Enabled,
				Lifetime:  sks.rollover.Interval.Duration(),
			},
		)
		if err != nil {
			return nil, false, err
		}
		if err = writeSignerToFile(sk, filePath); err != nil {
			return nil, false, err
		}
		pks.addCurrentJWK(pk)
		return sk, true, nil
	}
	if addPublicKeysToJWKS {
		pk, err := signerToPublicJWK(
			signer, alg, keyLifetimeConf{
				NowIssued: false,
				Expires:   sks.rollover.Enabled,
				Lifetime:  sks.rollover.Interval.Duration(),
			},
		)
		if err != nil {
			return nil, false, err
		}
		pks.addCurrentJWK(pk)
	}
	return signer, addPublicKeysToJWKS, nil
}

// GenerateNewKeys generates a new set of keys
func (sks *privateKeyStorageMultiAlg) GenerateNewKeys(pks *pkCollection, pksOnChange func() error) error {
	futureKeys := NewJWKS()
	for _, alg := range sks.algs {
		skNext, err := readSignerFromFile(sks.keyFilePath(alg, true), alg)
		if err != nil {
			// if the next sk file does not yet exist, generate it
			skNext, err = generateStoreAndSetNextPrivateKey(
				pks, alg, sks.rsaKeyLen, keyLifetimeConf{
					Expires:  sks.rollover.Enabled,
					Lifetime: sks.rollover.Interval.Duration(),
				}, sks.keyFilePath(alg, true), false,
			)
			if err != nil {
				return err
			}
		}
		sks.signers[alg] = skNext
		if err = errors.WithStack(os.Rename(sks.keyFilePath(alg, true), sks.keyFilePath(alg, false))); err != nil {
			return err
		}

		sk, pk, err := generateKeyPair(
			alg, sks.rsaKeyLen, keyLifetimeConf{
				Expires:  sks.rollover.Enabled,
				Lifetime: sks.rollover.Interval.Duration(),
				Nbf:      &unixtime.Unixtime{Time: pks.jwks[1].MinimalExpirationTime().Add(-10 * time.Second)},
			},
		)
		if err != nil {
			return err
		}
		if err = writeSignerToFile(sk, sks.keyFilePath(alg, false)); err != nil {
			return err
		}
		if err = futureKeys.AddKey(pk); err != nil {
			return errors.WithStack(err)
		}
	}
	pks.rotate(futureKeys)
	return pksOnChange()
}
