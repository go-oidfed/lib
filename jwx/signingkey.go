package jwx

import (
	"crypto"

	"github.com/jwx-go/compsig/v4"
)

// SigningKey is the interface for cryptographic private keys used for signing.
// It is satisfied by all standard library private key types (which implement
// crypto.Signer) and by composite signature keys via an internal wrapper.
type SigningKey interface {
	Public() crypto.PublicKey
}

// compsigSigningKey wraps *compsig.PrivateKey to satisfy the SigningKey
// interface. compsig.PrivateKey.Public() returns *compsig.PublicKey, not
// crypto.PublicKey, so it does not natively satisfy SigningKey.
type compsigSigningKey struct {
	sk *compsig.PrivateKey
}

func (w *compsigSigningKey) Public() crypto.PublicKey {
	return w.sk.Public()
}

// unwrapSigningKey returns the raw key to pass to jws.Sign. For composite
// keys, jws.Sign expects *compsig.PrivateKey, not the wrapper.
func unwrapSigningKey(key SigningKey) any {
	if w, ok := key.(*compsigSigningKey); ok {
		return w.sk
	}
	return key
}
