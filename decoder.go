package public_key_decoder

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
)

type PublicKeyDecoder struct{}

func NewPublicKeyDecoder() PublicKeyDecoder {
	return PublicKeyDecoder{}
}

func (decoder PublicKeyDecoder) GetRSAPublicKeyFromJWK(jwk JSONWebKey) (RSAPublicKey, error) {
	decodedN, err := base64.StdEncoding.DecodeString(jwk.N)
	if err != nil {
		return RSAPublicKey{}, err
	}
	var keyN big.Int
	keyN.SetBytes(decodedN)

	keyE, err := decodeStringToUint64(jwk.E)
	if err != nil {
		return RSAPublicKey{}, err
	}

	return RSAPublicKey{
		Id: jwk.Kid,
		Key: rsa.PublicKey{
			N: &keyN,
			E: int(keyE),
		},
	}, nil
}

func (decoder PublicKeyDecoder) GetRSAPublicKeyMapFromJWKs(jwks JWKs) (RSAPublicKeyMap, error) {
	keyMap := make(RSAPublicKeyMap)
	for _, jwk := range jwks {
		key, err := decoder.GetRSAPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		keyMap[key.Id] = key
	}
	return keyMap, nil
}

func decodeStringToUint64(str string) (uint64, error) {
	bytes, err := decodeStringToBytes(str)
	if err != nil {
		return 0, err
	}

	data := make([]byte, 8)
	for i, v := range bytes {
		data[8-len(bytes)+i] = v
	}

	return binary.BigEndian.Uint64(data), nil
}

func decodeStringToBytes(str string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(str)
}
