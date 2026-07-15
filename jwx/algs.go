package jwx

import (
	"github.com/jwx-go/compsig/v4"
	"github.com/jwx-go/ed448/v4"
	"github.com/jwx-go/es256k/v4"
	jwxmldsa "github.com/jwx-go/mldsa/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

var supportedAlgs = []jwa.SignatureAlgorithm{
	jwa.ES512(),
	jwa.ES256(),
	jwa.ES384(),
	es256k.ES256K(),
	jwa.EdDSA(),
	jwa.EdDSAEd25519(),
	ed448.EdDSAEd448(),
	jwa.PS512(),
	jwa.PS256(),
	jwa.PS384(),
	jwa.RS512(),
	jwa.RS384(),
	jwa.RS256(),
	jwxmldsa.MLDSA44(),
	jwxmldsa.MLDSA65(),
	jwxmldsa.MLDSA87(),
	compsig.MLDSA44ES256(),
	compsig.MLDSA65ES256(),
	compsig.MLDSA87ES384(),
	compsig.MLDSA44Ed25519(),
	compsig.MLDSA65Ed25519(),
	compsig.MLDSA87Ed448(),
}
var supportedAlgsStr []string

func init() {
	for _, alg := range supportedAlgs {
		supportedAlgsStr = append(supportedAlgsStr, alg.String())
	}
}

// SupportedAlgs returns the supported signing algorithms as a slice of jwa.SignatureAlgorithm
func SupportedAlgs() []jwa.SignatureAlgorithm {
	return supportedAlgs
}

// SupportedAlgsStrings returns the supported signing algorithms as a slice of
// string
func SupportedAlgsStrings() []string {
	return supportedAlgsStr
}
