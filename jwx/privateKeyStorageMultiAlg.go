package jwx

import (
	"crypto"
	"fmt"
	"slices"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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

func (sks privateKeyStorageMultiAlg) keyFilePath(alg jwa.SignatureAlgorithm) string {
	return fmt.Sprintf("%s/%s_%s.pem", sks.keyDir, sks.typeID, alg.String())
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

func (sks *privateKeyStorageMultiAlg) initKeyRotation(pks *jwksSlice, pksOnChange func() error) {
	if !sks.rollover.Enabled {
		return
	}
	go time.AfterFunc(
		time.Until((*pks)[0].MinimalExpirationTime().Time), func() {
			if err := sks.GenerateNewKeys(pks, pksOnChange); err != nil {
				log.Error(err)
			}
			ticker := time.NewTicker(time.Duration(sks.rollover.Interval) * time.Second)
			for range ticker.C {
				if err := sks.GenerateNewKeys(pks, pksOnChange); err != nil {
					log.Error(err)
				}
			}
		},
	)
}

// Load loads the private keys from disk and if necessary generates missing keys
func (sks *privateKeyStorageMultiAlg) Load(pks *jwksSlice, pksOnChange func() error) error {
	populatePKFromSK := false
	if sks.signers == nil {
		sks.signers = make(map[jwa.SignatureAlgorithm]crypto.Signer)
	}
	if len(*pks) == 0 {
		*pks = []JWKS{NewJWKS()}
		populatePKFromSK = true
	}
	pksChanged := false
	// load oidc keys
	for _, alg := range sks.algs {
		filePath := sks.keyFilePath(alg)
		signer, err := readSignerFromFile(filePath, alg)
		if err != nil {
			// could not load key, generating a new one for this alg
			sk, pk, err := generateKeyPair(
				alg, sks.rsaKeyLen, sks.rollover.Enabled, time.Duration(sks.rollover.Interval)*time.Second,
			)
			if err != nil {
				return err
			}
			if err = writeSignerToFile(sk, sks.keyFilePath(alg)); err != nil {
				return err
			}
			if err = (*pks)[0].AddKey(pk); err != nil {
				return errors.WithStack(err)
			}
			pksChanged = true
			signer = sk
		} else if populatePKFromSK {
			pk, err := signerToPublicJWK(
				signer, alg, false, sks.rollover.Enabled, time.Duration(sks.rollover.Interval)*time.Second,
			)
			if err != nil {
				return err
			}
			if err = (*pks)[0].AddKey(pk); err != nil {
				return errors.WithStack(err)
			}
		}
		sks.signers[alg] = signer
	}
	if populatePKFromSK || pksChanged {
		if err := pksOnChange(); err != nil {
			return err
		}
	}
	sks.initKeyRotation(pks, pksOnChange)
	return nil
}

// GenerateNewKeys generates a new set of keys
func (sks *privateKeyStorageMultiAlg) GenerateNewKeys(pks *jwksSlice, pksOnChange func() error) error {
	newKeys := NewJWKS()
	for _, alg := range sks.algs {
		sk, pk, err := generateKeyPair(
			alg, sks.rsaKeyLen, sks.rollover.Enabled, time.Duration(sks.rollover.Interval)*time.Second,
		)
		if err != nil {
			return err
		}
		if err = writeSignerToFile(sk, sks.keyFilePath(alg)); err != nil {
			return err
		}
		if err = newKeys.AddKey(pk); err != nil {
			return errors.WithStack(err)
		}
		sks.signers[alg] = sk
	}
	if len(*pks) <= sks.rollover.NumberOfOldKeysKeptInJWKS {
		*pks = append([]JWKS{newKeys}, *pks...)
	} else {
		for i := len(*pks) - 1; i > 0; i-- {
			(*pks)[i] = (*pks)[i-1]
		}
		(*pks)[0] = newKeys
	}
	return pksOnChange()
}
