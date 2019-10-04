package public_key_handler

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
)

type PublicKeyHandler struct{
	httpClient *http.Client
}

type JWKResponse struct {
	JWKs []JSONWebKey `json:"jwks"`
}

func NewPublicKeyHandler() PublicKeyHandler {
	return PublicKeyHandler{
		httpClient: &http.Client{},
	}
}

func (handler PublicKeyHandler) GetPublicKeyMapFromJWKEndpoint(endpoint string) (RSAPublicKeyMap,error) {
	response,err := handler.httpClient.Get(endpoint)
	if err != nil {
		return nil,err
	}
	body,err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil,err
	}
	var jwkResponse JWKResponse
	if err := json.Unmarshal(body,&jwkResponse); err != nil {
		return nil,err
	}
	return handler.getRSAPublicKeyMapFromJWKs(jwkResponse.JWKs)
}

func (handler PublicKeyHandler) getRSAPublicKeyFromJWK(jwk JSONWebKey) (RSAPublicKey, error) {
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

func (handler PublicKeyHandler) getRSAPublicKeyMapFromJWKs(jwks JWKs) (RSAPublicKeyMap, error) {
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
