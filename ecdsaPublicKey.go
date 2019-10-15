package public_key_handler

import "crypto/ecdsa"

type ECDSAPublicKey struct {
	Id  string
	Key ecdsa.PublicKey
}

type ECDSAPublicKeyMap map[string]ecdsa.PublicKey
