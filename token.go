package jwtToken

import (
	"errors"
	"fmt"
	"gopkg.in/dgrijalva/jwt-go.v2"
	"net/http"
	"os"
)

var (
	InvalidSecret = errors.New("JWT secret cannot be an empty string")
)

// Token interface used primarily for mocking
type Token interface {
	getSecret() error
	CreateToken(map[string]interface{}) (string, error)
	ParseTokenFromRequest(*http.Request) (*jwt.Token, error)
}

// Instantiate new JwtToken type, creates the map of claims
// and sets it to zero
// return *jwtToken type
func New() *JwtToken {
	return &JwtToken{Claims: make(map[string]interface{}, 0)}
}

// Methods used primarily for mocking
// @params token interface
// return error if set, nil if not
func GetSecret(t Token) error {
	err := t.getSecret()

	if err != nil {
		return err
	}

	return nil
}

// Method used primarily for mocking
// @params token interface, token claims map[string]interface{}
func CreateToken(t Token, claims map[string]interface{}) (string, error) {
	str, err := t.CreateToken(claims)

	if err != nil {
		return "", err
	}

	return str, nil
}

func ParseTokenFromRequest(t Token, r *http.Request) (*jwt.Token, error) {
	token, err := t.ParseTokenFromRequest(r)

	if err != nil {
		return nil, err
	}

	return token, nil 
}

type JwtToken struct {
	Claims      map[string]interface{}
	TokenString string
	secret      string
	Err         error
	*jwt.Token
}

// Get the secret token stored in the env variable "JWT_SECRET"
// return error if secret exists return nil, otherwise return error
func (j *JwtToken) getSecret() error {
	j.secret = os.Getenv("JWT_SECRET")

	if j.secret == "" {
		j.TokenString = ""
		j.Err = InvalidSecret
		return j.Err
	}

	return nil
}

// Creates a token string based on HS256 signingMethod
/// @params claims map[string]interface{}
// returns the token string if success, or otherwise an err
func (j *JwtToken) CreateToken(claims map[string]interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	j.Claims = claims
	tokenString, err := token.SignedString([]byte(j.secret))

	if err != nil {
		return "", err
	}

	j.TokenString = tokenString

	return j.TokenString, nil
}

// Parses a token string, must be signed with HS256 signingMethod
// @params tokenString token that was generated
// return *jwt.Token type set to nil if not successful
// error set to nil if successful, otherwise error
func (j *JwtToken) ParseToken(tokenString string) (*jwt.Token, error) {
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "HS256" {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(j.secret), nil
	})

	if err == nil && t.Valid {
		return t, nil
	}

	return nil, err
}

// Parses a token string, from a web request.
// Must be signed with HS256 signingMethod
// @params *http.Request type
// return *jwt.Token type set to nil if not successful
// error set to nil if successful, otherwise error
func (j *JwtToken) ParseTokenFromRequest(request *http.Request) (*jwt.Token, error) {
	t, err := jwt.ParseFromRequest(request, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(j.secret), nil
	})

	return t, err
}
