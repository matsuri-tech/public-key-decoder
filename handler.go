package public_key_handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
)

type PublicKeyHandler struct {
	httpClient *http.Client
}

type RSAJWKResponse struct {
	JWKs []RSAJSONWebKey `json:"jwks"`
}

type ECDSAJWKResponse struct {
	JWKs []ECDSAJSONWebKey `json:"jwks"`
}

func InvalidEllipticCurve(str string) error {
	return errors.New("invalid elliptic curve: " + str)
}

func NewPublicKeyHandler() PublicKeyHandler {
	return PublicKeyHandler{
		httpClient: &http.Client{},
	}
}

func (handler PublicKeyHandler) GetRSAPublicKeyMapFromJWKEndpoint(endpoint string) (RSAPublicKeyMap, error) {
	response, err := handler.httpClient.Get(endpoint)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var jwkResponse RSAJWKResponse
	if err := json.Unmarshal(body, &jwkResponse); err != nil {
		return nil, err
	}
	return handler.getRSAPublicKeyMapFromJWKs(jwkResponse.JWKs)
}

func (handler PublicKeyHandler) getRSAPublicKeyFromJWK(jwk RSAJSONWebKey) (RSAPublicKey, error) {
	decodedN, err := base64.RawURLEncoding.DecodeString(jwk.N)
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

func (handler PublicKeyHandler) getRSAPublicKeyMapFromJWKs(jwks RSAJWKs) (RSAPublicKeyMap, error) {
	keyMap := make(RSAPublicKeyMap)
	for _, jwk := range jwks {
		key, err := handler.getRSAPublicKeyFromJWK(jwk)
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

func (handler PublicKeyHandler) GetECDSAPublicKeyMapFromJWKEndpoint(endpoint string) (ECDSAPublicKeyMap, error) {
	response, err := handler.httpClient.Get(endpoint)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var jwkResponse ECDSAJWKResponse
	if err := json.Unmarshal(body, &jwkResponse); err != nil {
		return nil, err
	}
	return handler.getECDSAPublicKeyMapFromJWKs(jwkResponse.JWKs)
}

func (handler PublicKeyHandler) getECDSAPublicKeyFromJWK(jwk ECDSAJSONWebKey) (ECDSAPublicKey, error) {
	decodedX, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return ECDSAPublicKey{}, err
	}
	var keyX big.Int
	keyX.SetBytes(decodedX)

	decodedY, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return ECDSAPublicKey{}, err
	}
	var keyY big.Int
	keyY.SetBytes(decodedY)

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	default:
		return ECDSAPublicKey{}, InvalidEllipticCurve(jwk.Crv)
	}

	return ECDSAPublicKey{
		Id: jwk.Kid,
		Key: ecdsa.PublicKey{
			Curve: curve,
			X:     &keyX,
			Y:     &keyY,
		},
	}, nil
}

func (handler PublicKeyHandler) getECDSAPublicKeyMapFromJWKs(jwks ECDSAJWKs) (ECDSAPublicKeyMap, error) {
	keyMap := make(ECDSAPublicKeyMap)
	for _, jwk := range jwks {
		key, err := handler.getECDSAPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		keyMap[key.Id] = key.Key
	}
	return keyMap, nil
}
