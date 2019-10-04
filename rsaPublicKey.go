package public_key_decoder

import "crypto/rsa"

type RSAPublicKey struct {
	Id  string
	Key rsa.PublicKey
}

type RSAPublicKeyMap map[string]RSAPublicKey
