package jwtToken

import (
	"errors"
	"fmt"
	"gopkg.in/dgrijalva/jwt-go.v2"
	"net/http"
	"os"
	"testing"
	"time"
)

type tokenTest struct {
	tokenString string
	claims      map[string]interface{}
	str         string
	secret      string
	err         error
}

func NewTokenTest() *tokenTest {
	return &tokenTest{claims: make(map[string]interface{}, 0)}
}

func (tk *tokenTest) getSecret() error {
	if tk.secret == "" {
		tk.tokenString = ""
		tk.err = InvalidSecret
		return tk.err
	}

	return nil
}

func (tk *tokenTest) CreateToken(claims map[string]interface{}) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = claims
	tk.claims = claims

	if tk.err != nil {
		tk.tokenString = ""
		return "", tk.err
	}

	tokenString, _ := token.SignedString([]byte(tk.secret))
	tk.tokenString = tokenString
	return tk.tokenString, nil
}

func (tk *tokenTest) ParseTokenFromRequest(r *http.Request) (*jwt.Token, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	tokenString, _ := token.SignedString([]byte(tk.secret))
	tk.tokenString = tokenString

	return token, nil
}

func TestGetSecret(t *testing.T) {
	var TokenData = []struct {
		secret      string
		tokenString string
		claims      map[string]interface{}
		err         error
	}{
		{
			secret: os.Getenv("JWT_SECRET"),
		},
		{
			secret:      "",
			tokenString: "",
			err:         InvalidSecret,
		},
	}

	tokenTest := NewTokenTest()

	for _, item := range TokenData {
		tokenTest.secret = item.secret
		err := GetSecret(tokenTest)

		if err != item.err {
			t.Errorf("Expected error to be %v, but got %v", item.err, err)
		}
	}
}

func TestCreateToken(t *testing.T) {
	var TokenData = []struct {
		secret      string
		tokenString string
		claims      map[string]interface{}
		valid       bool
		str         string
		err         error
	}{
		{
			secret: os.Getenv("JWT_SECRET"),
			claims: map[string]interface{}{
				"nbf": float64(time.Now().Unix() - 10),
				"exp": float64(time.Now().Unix() + 10),
			},
		},
		{
			secret:      os.Getenv("JWT_SECRET"),
			str:         "",
			tokenString: "",
			err:         errors.New("Error creating token"),
		},
	}

	tokenTest := NewTokenTest()

	for _, item := range TokenData {
		tokenTest.secret = item.secret
		GetSecret(tokenTest)
		tokenTest.err = item.err
		token, err := CreateToken(tokenTest, item.claims)

		if err != item.err {
			t.Errorf("Expected error to be %v, but got %v", item.err, err)
		}

		if token != tokenTest.tokenString {
			t.Errorf("Expected token to be \"\", but got %v", token)
		}

	}
}

func TestParseToken(t *testing.T) {
	var TokenData = []struct {
		name        string
		tokenString string
		errors      string
		jwtToken    *jwt.Token
		secret      string
	}{
		{
			name:        "basic RS256 token, wrong signing method",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			errors:      "Unexpected signing method: RS256",
			jwtToken:    &jwt.Token{},
			secret:      os.Getenv("JWT_SECRET"),
		},

		{
			name:        "basic HS256 token valid",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.AL4kyvAw8DpxKJbmPSEtJAdT0jqM55HcJWnvIZ1JaKk",
			jwtToken: &jwt.Token{
				Raw: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.AL4kyvAw8DpxKJbmPSEtJAdT0jqM55HcJWnvIZ1JaKk",
				Header: map[string]interface{}{
					"alg": "HS256", "typ": "JWT",
				},
				Claims:    map[string]interface{}{},
				Signature: "",
				Valid:     true,
			},
			secret: os.Getenv("JWT_SECRET"),
		},
		{
			name:        "basic HS256 token invalid",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.LwimMJA3puF3ioGeS-tfczR3370GXBZMIL-bdpu4hOU",
			errors:      "signature is invalid",
			jwtToken: &jwt.Token{
				Raw: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.LwimMJA3puF3ioGeS-tfczR3370GXBZMIL-bdpu4hOU",
				Header: map[string]interface{}{
					"alg": "HS256", "typ": "JWT",
				},
				Claims:    map[string]interface{}{},
				Signature: "",
				Valid:     false,
			},
			secret: os.Getenv("JWT_SECRET"),
		},
	}

	jwtToken := New()

	for _, token := range TokenData {
		jwtToken.secret = token.secret
		jwt, err := jwtToken.ParseToken(token.tokenString)

		errString := fmt.Sprint(err)

		if err != nil && errString != token.errors {
			t.Errorf("Expected error to be %v, but got %v", token.errors, errString)
		}

		if jwt != nil && jwt.Valid != token.jwtToken.Valid {
			t.Errorf("Expected token to be %v, but got %v", token.jwtToken.Valid, jwt.Valid)
		}
	}
}

func TestParseTokenFromRequest(t *testing.T) {
	var TokenData = []struct {
		name        string
		tokenString string
		errors      string
		jwtToken    *jwt.Token
		secret      string
	}{
		{
			name:        "basic RS256 token, wrong signing method",
			tokenString: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
			errors:      "Unexpected signing method: RS256",
			jwtToken:    &jwt.Token{},
			secret:      os.Getenv("JWT_SECRET"),
		},

		{
			name:        "basic HS256 token valid",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.AL4kyvAw8DpxKJbmPSEtJAdT0jqM55HcJWnvIZ1JaKk",
			jwtToken: &jwt.Token{
				Raw: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.AL4kyvAw8DpxKJbmPSEtJAdT0jqM55HcJWnvIZ1JaKk",
				Header: map[string]interface{}{
					"alg": "HS256", "typ": "JWT",
				},
				Claims:    map[string]interface{}{},
				Signature: "",
				Valid:     true,
			},
			secret: os.Getenv("JWT_SECRET"),
		},
		{
			name:        "basic HS256 token invalid",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.LwimMJA3puF3ioGeS-tfczR3370GXBZMIL-bdpu4hOU",
			errors:      "signature is invalid",
			jwtToken: &jwt.Token{
				Raw: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.LwimMJA3puF3ioGeS-tfczR3370GXBZMIL-bdpu4hOU",
				Header: map[string]interface{}{
					"alg": "HS256", "typ": "JWT",
				},
				Claims:    map[string]interface{}{},
				Signature: "",
				Valid:     false,
			},
			secret: os.Getenv("JWT_SECRET"),
		},
	}

	jwtToken := New()

	for _, token := range TokenData {
		jwtToken.secret = token.secret
		r, _ := http.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %v", token.tokenString))
		jwt, err := jwtToken.ParseTokenFromRequest(r)

		errString := fmt.Sprint(err)

		if err != nil && errString != token.errors {
			t.Errorf("Expected error to be %v, but got %v", token.errors, errString)
		}

		if jwt != nil && jwt.Valid != token.jwtToken.Valid {
			t.Errorf("Expected token to be %v, but got %v", token.jwtToken.Valid, jwt.Valid)
		}
	}
}
