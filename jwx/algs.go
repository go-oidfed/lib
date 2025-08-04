package jwx

import (
	"github.com/lestrrat-go/jwx/v3/jwa"
)

var supportedAlgs = []jwa.SignatureAlgorithm{
	jwa.ES512(),
	jwa.ES256(),
	jwa.ES384(),
	jwa.EdDSA(),
	jwa.PS512(),
	jwa.PS256(),
	jwa.PS384(),
	jwa.RS512(),
	jwa.RS384(),
	jwa.RS256(),
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
