package kms

import (
	"crypto"
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/go-oidfed/lib/jwx"
)

// LegacyFilesystemKMS provides a read-only BasicKeyManagementSystem backed by legacy
// key file layout (<type>_<alg>.pem). It enables migration by exposing GetForAlgs
// based on the legacy files, without supporting rotation.
type LegacyFilesystemKMS struct {
	Dir     string
	TypeID  string
	Algs    []jwa.SignatureAlgorithm
	signers map[string]crypto.Signer // kid -> signer
}

func (l *LegacyFilesystemKMS) legacyKeyFilePath(alg jwa.SignatureAlgorithm) string {
	return fmt.Sprintf("%s/%s_%s.pem", l.Dir, l.TypeID, alg.String())
}

func (l *LegacyFilesystemKMS) Load() error {
	l.signers = make(map[string]crypto.Signer)
	for _, alg := range l.Algs {
		signer, err := jwx.ReadSignerFromFile(l.legacyKeyFilePath(alg), alg)
		if err != nil {
			continue
		}
		_, kid, err := jwx.SignerToPublicJWK(signer, alg)
		if err != nil {
			continue
		}
		l.signers[kid] = signer
	}
	return nil
}

func (l *LegacyFilesystemKMS) GetForAlgs(algs ...string) (crypto.Signer, jwa.SignatureAlgorithm) {
	for _, alg := range l.Algs {
		for _, signer := range l.signers {
			if slices.Contains(algs, alg.String()) {
				return signer, alg
			}
		}
	}
	return nil, jwa.SignatureAlgorithm{}
}

func (l *LegacyFilesystemKMS) GetDefault() (crypto.Signer, jwa.SignatureAlgorithm) {
	if len(l.Algs) == 0 {
		return nil, jwa.SignatureAlgorithm{}
	}
	return l.GetForAlgs(l.Algs[0].String())
}
