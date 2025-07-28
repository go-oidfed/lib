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

type privateKeyStorageSingleAlg struct {
	typeID    string
	signer    crypto.Signer
	alg       jwa.SignatureAlgorithm
	keyDir    string
	rsaKeyLen int
	rollover  RolloverConf
}

func (sks privateKeyStorageSingleAlg) keyFilePath() string {
	return fmt.Sprintf("%s/%s_%s.pem", sks.keyDir, sks.typeID, sks.alg.String())
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

func (sks *privateKeyStorageSingleAlg) initKeyRotation(pks *jwksSlice, pksOnChange func() error) {
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

// Load loads the key from disk or generates a new one if the key does not exist on disk
func (sks *privateKeyStorageSingleAlg) Load(pks *jwksSlice, pksOnChange func() error) error {
	signer, err := readSignerFromFile(sks.keyFilePath(), sks.alg)
	if err != nil {
		log.Warn(err)
		if err = sks.GenerateNewKeys(pks, pksOnChange); err != nil {
			return err
		}
		sks.initKeyRotation(pks, pksOnChange)
		return nil
	}
	sks.signer = signer

	if len(*pks) == 0 {
		// This is only for the case that there is no keys.jwks yet,
		// but there was a private key file.
		set := NewJWKS()
		pk, err := signerToPublicJWK(
			signer, sks.alg, false, sks.rollover.Enabled, time.Duration(sks.rollover.Interval)*time.Second,
		)
		if err != nil {
			return err
		}
		if err = set.AddKey(pk); err != nil {
			return errors.WithStack(err)
		}
		*pks = []JWKS{set}
		if err = pksOnChange(); err != nil {
			return err
		}
	}
	sks.initKeyRotation(pks, pksOnChange)
	return nil
}

// GenerateNewKeys generates a new key
func (sks *privateKeyStorageSingleAlg) GenerateNewKeys(pks *jwksSlice, pksOnChange func() error) error {
	newKeys := NewJWKS()
	sk, pk, err := generateKeyPair(
		sks.alg, sks.rsaKeyLen, sks.rollover.Enabled, time.Duration(sks.rollover.Interval)*time.Second,
	)
	if err != nil {
		return err
	}
	if err = writeSignerToFile(sk, sks.keyFilePath()); err != nil {
		return err
	}
	if err = newKeys.AddKey(pk); err != nil {
		return errors.WithStack(err)
	}
	sks.signer = sk
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
