package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/dkushche/auth_service/internal/account"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
)

var privKey *ecdsa.PrivateKey

func generateKey(key_path string) error {
	var x509Encoded []byte
	var err error

	if privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return err
	}
	if x509Encoded, err = x509.MarshalECPrivateKey(privKey); err != nil {
		return err
	}
	if err = ioutil.WriteFile(
		key_path,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded}),
		0644,
	); err != nil {
		return err
	}

	return nil
}

func readKey(key_path string) error {
	var raw []byte
	var block *pem.Block
	var err error

	if raw, err = ioutil.ReadFile(key_path); err != nil {
		return err
	}

	if block, _ = pem.Decode(raw); err != nil {
		return err
	}

	x509Encoded := block.Bytes
	if privKey, err = x509.ParseECPrivateKey(x509Encoded); err != nil {
		return err
	}

	return nil
}

func InitKey(key_path string) error {
	if _, err := os.Stat(key_path); err != nil {
		if err := generateKey(key_path); err != nil {
			return err
		}
	} else {
		if err := readKey(key_path); err != nil {
			return err
		}
	}

	return nil
}

func GenerateToken(uaccount *account.Account, uyggAddr string) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("no private key")
	}

	token := jwt.New()

	token.Set(jwt.ExpirationKey, time.Now().AddDate(0, 0, 1))
	token.Set(jwt.AudienceKey, uyggAddr)

	payload, err := jwt.Sign(token, jwa.ES256, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signed payload: %w", err)
	}

	return payload, nil
}

func VerifyToken(payload []byte, uyggAddr string) error {
	if privKey == nil {
		return errors.New("no private key")
	}

	authToken, err := jwt.Parse(
		payload,
		jwt.WithValidate(true),
		jwt.WithVerify(jwa.ES256, &privKey.PublicKey),
	)

	if err != nil {
		fmt.Printf("failed to parse JWT token: %s\n", err)
		return err
	}

	val, ok := authToken.Get(jwt.AudienceKey)
	if !ok {
		return errors.New("no audience key")
	} else {
		if val.([]string)[0] != uyggAddr {
			return errors.New("incorrect yggdrasil user address")
		}
	}

	val, ok = authToken.Get(jwt.ExpirationKey)
	if !ok {
		return errors.New("no expiration time key")
	} else {
		if time.Now().Unix() >= val.(time.Time).Unix() {
			return errors.New("token expired")
		}
	}

	return nil
}
