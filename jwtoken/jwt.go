package jwtoken

import (
	"fmt"
	//"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/log"
)

type JWT struct {
	publicKey []byte
	logger    log.Logger
}

func NewJWT(publicKey []byte, logger log.Logger) JWT {
	return JWT{
		publicKey: publicKey,
		logger:    logger,
	}
}

func (j JWT) Validate(token string) (interface{}, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return "", fmt.Errorf("validate: parse key: %w", err)
	}

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims, nil
}
