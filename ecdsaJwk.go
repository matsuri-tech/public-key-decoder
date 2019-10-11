package public_key_handler

type ECDSAJSONWebKey struct {
	Kty string   `json:"kty"`
	Crv string   `json:"crv"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5c []string `json:"x5c"`
}

type ECDSAJWKs []ECDSAJSONWebKey
