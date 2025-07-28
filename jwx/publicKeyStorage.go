package jwx

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/zachmann/go-utils/fileutils"
)

type jwksSlice []JWKS

type aggregatedPublicKeyStorage map[string]*jwksSlice

// Load loads the public keys from disk
func (pks *aggregatedPublicKeyStorage) Load(filepath string) error {
	data, err := fileutils.ReadFile(filepath)
	if err != nil {
		log.Warn(err.Error())
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return errors.WithStack(json.Unmarshal(data, pks))
}

// Save saves the public keys to disk
func (pks aggregatedPublicKeyStorage) Save(filepath string) error {
	data, err := json.Marshal(pks)
	if err != nil {
		return errors.WithStack(err)
	}
	if err = os.WriteFile(filepath, data, 0600); err != nil {
		return errors.WithStack(err)
	}
	return nil
}
