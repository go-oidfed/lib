package jwx

import (
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func newSingleAlgPrivateKeyStorage(
	typeID string, alg jwa.SignatureAlgorithm, rotationConf RolloverConf, rsaKeyLen int, keyDir string,
) privateKeyStorage {
	return &privateKeyStorageMultiAlg{
		typeID:     typeID,
		algs:       []jwa.SignatureAlgorithm{alg},
		defaultAlg: alg,
		rollover:   rotationConf,
		rsaKeyLen:  rsaKeyLen,
		keyDir:     keyDir,
	}
}
