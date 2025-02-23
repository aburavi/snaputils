package apisignature

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/aburavi/snaputils/async"

	"google.golang.org/grpc/status"
)

var publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkgmyeA4xzrTx8BGK75pe
xoZq+TaaUaMZpoRWN2ryyJiRzM7QB1pb/IkyrPNUfMu4g4OzlDpdWhhF5G5/3f1s
l5RFUjj4vBYzu6hussNhqnyNlKpEw5Lm9e1O8ixgmwmZSFw8dQjwPZmkFoQbIxUe
OvfgAqkLEp15eioN0G3pm1t+kA2yBjZ89Qk57YZNxBfBFddYmAfVnC5f2mfehZWC
4MeG2j0WkACMCF1HM3Uy4IMdSzupJU8pG1NTeNmibf23Px0TPRabhczu/39gJHg6
PrjGeqeD5RK82zECuc5nFzx06rbixeG/1bszLVSmgOSQ0DWvop07KaATW8pPvc9C
bQIDAQAB
-----END PUBLIC KEY-----`)

// mode=0 -> grpc
// mode=1 -> http
func RSA_OAEP_Encrypt(secretMessage string, clientSecret string, mode int) (string, error) {
	s := secretMessage
	block, _ := pem.Decode(publicKey)
	if block.Type != "PUBLIC KEY" {
		er1 := fmt.Sprintf("error decoding public key from pem")
		derr := status.Errorf(4001102, er1)
		return "None", derr
	}
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		er2 := fmt.Sprintf("error parsing key")
		derr := status.Errorf(4001102, er2)
		return "None", derr
	}
	var ok bool
	var pubkey *rsa.PublicKey
	if pubkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		er3 := fmt.Sprintf("unable to parse public key")
		derr := status.Errorf(4001102, er3)
		return "None", derr
	}
	rng := rand.Reader
	ciphertext, err1 := rsa.EncryptOAEP(sha256.New(), rng, pubkey, []byte(s), nil)
	if err1 != nil {
		er4 := fmt.Sprintf(err1.Error())
		derr := status.Errorf(4001102, er4)
		return "None", derr
	}
	ct := hex.EncodeToString(ciphertext)

	return ct, nil
}

// mode=0 -> grpc
// mode=1 -> http
func RSA_OAEP_Decrypt_Http(msg, sig, clientId string, mode int) (string, bool, error) {
	valsecret := ""
	valpkey := ""

	if mode == 0 {
		ddata, err1 := getPublicKeyGrpc(clientId)
		if err1 != nil {
			er1 := fmt.Sprintf("service hit failed: %s\n", err1)
			derr := status.Errorf(4001102, er1)
			return "None", false, derr
		}

		val := strings.Split(ddata, "|")
		valsecret = val[0]
		valpkey = val[1]

	} else if mode == 1 {
		ddata, err1 := getPublicKeyHttp(clientId)
		if err1 != nil {
			er1 := fmt.Sprintf("service hit failed: %s\n", err1)
			derr := status.Errorf(4001102, er1)
			return "None", false, derr
		}

		val := strings.Split(ddata, "|")
		valsecret = val[0]
		valpkey = val[1]
		fmt.Sprintf("val: %s\n", ddata)
	} else {
		return "Unknown mode", false, nil
	}

	secret := valsecret
	block, _ := pem.Decode([]byte(valpkey))

	if block.Type != "PUBLIC KEY" {
		er2 := fmt.Sprintf("error decoding public key from pem")
		derr := status.Errorf(4001102, er2)
		return "None", false, derr
	}

	key, errr := x509.ParsePKIXPublicKey(block.Bytes)

	if errr != nil {
		er2 := fmt.Sprintf("error verify public key from pem %s\n", errr)
		derr := status.Errorf(4001102, er2)
		return "None", false, derr
	}

	pubKey := key.(*rsa.PublicKey)

	signature, err1 := hex.DecodeString(sig)
	if err1 != nil {
		er2 := fmt.Sprintf("error decoding message %s\n", err1)
		derr := status.Errorf(4001102, er2)
		return "None", false, derr
	}
	//rng := rand.Reader
	hashed := sha256.Sum256([]byte(msg))

	errr2 := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	if errr2 != nil {
		fmt.Println("Error Verify: ", msg)
		er2 := fmt.Sprintf("error verify message %s\n", errr2)
		derr := status.Errorf(4001102, er2)
		return "None", false, derr
	}

	return secret, true, nil
}

func RSA_OAEP_Decrypt(cipherText, clientid string) (string, error) {
	var future1 async.Future
	future1 = async.Exec(func() (interface{}, error) {
		data_userkey, err1 := getUserKeyGrpc(clientid)
		return data_userkey, err1
	})

	val, err2 := future1.Await()
	if err2 != nil {
		er1 := fmt.Sprintf("service hit failed: %s\n", err2)
		derr := status.Errorf(4001202, er1)
		return "None", derr
	}

	ct, _ := hex.DecodeString(cipherText)
	block, _ := pem.Decode([]byte(val.(string)))
	if block.Type != "RSA PRIVATE KEY" {
		er2 := fmt.Sprintf("error decoding private key from pem")
		derr := status.Errorf(4001202, er2)
		return "None", derr
	}

	parsedKey, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err3 != nil {
		er3 := fmt.Sprintf("error parsing key")
		derr := status.Errorf(4001202, er3)
		return "None", derr
	}
	rng := rand.Reader
	message, err4 := rsa.DecryptOAEP(sha256.New(), rng, parsedKey, ct, nil)
	if err4 != nil {
		er4 := fmt.Sprintf(err4.Error())
		derr := status.Errorf(4001202, er4)
		return "None", derr
	}

	return string(message), nil
}

func AUTH_RSA_OAEP_Encrypt(secretMessage string, clientid string) (string, error) {
	ddata, err1 := getPrivateKeyGrpc(clientid)
	if err1 != nil {
		er1 := fmt.Sprintf("service hit failed: %s\n", err1)
		derr := status.Errorf(4001002, er1)
		return "None", derr
	}
	val := strings.Split(ddata, "|")
	//valsecret := val[0]
	valpkey := val[1]

	//privateKey := []byte(fmt.Sprintf("`" + valpkey + "`"))

	block, _ := pem.Decode([]byte(valpkey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		er1 := fmt.Sprintf("error decoding private key from pem with key %s\n", block)
		derr := status.Errorf(4001002, er1)
		return "", derr
	}

	pvKey, err1 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err1 != nil {
		er2 := fmt.Sprintf("error parsing key")
		derr := status.Errorf(4001002, er2)
		return "", derr
	}

	rng := rand.Reader
	dmessage := secretMessage
	messageBytes := bytes.NewBufferString(dmessage)
	hash := sha256.New()
	hash.Write(messageBytes.Bytes())
	digest := hash.Sum(nil)

	ciphertext, err2 := rsa.SignPKCS1v15(rng, pvKey, crypto.SHA256, digest)
	if err2 != nil {
		er4 := fmt.Sprintf(err2.Error())
		derr := status.Errorf(4001002, er4)
		return "", derr
	}

	ct := hex.EncodeToString(ciphertext)

	return ct, nil
}

func TRX_RSA_OAEP_Encrypt(secretMessage string, clientid string) (string, error) {
	s := secretMessage
	ddata, err1 := getPublicKeyGrpc(clientid)
	if err1 != nil {
		er1 := fmt.Sprintf("service hit failed: %s\n", err1)
		derr := status.Errorf(4001002, er1)
		return "None", derr
	}

	val := strings.Split(ddata, "|")
	//valsecret := val[0]
	valpubkey := val[1]
	fmt.Println("public Key: " + valpubkey)

	block, _ := pem.Decode([]byte(valpubkey))
	if block == nil || block.Type != "PUBLIC KEY" {
		er1 := fmt.Sprintf("error decoding public key from pem with key %s\n", block)
		derr := status.Errorf(4001002, er1)
		return "", derr
	}
	parsedKey, err1 := x509.ParsePKIXPublicKey(block.Bytes)
	if err1 != nil {
		er2 := fmt.Sprintf("error parsing key")
		derr := status.Errorf(4001002, er2)
		return "", derr
	}
	var ok bool
	var pubkey *rsa.PublicKey
	if pubkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		er3 := fmt.Sprintf("unable to parse public key")
		derr := status.Errorf(4001002, er3)
		return "", derr
	}
	rng := rand.Reader
	ciphertext, err2 := rsa.EncryptOAEP(sha256.New(), rng, pubkey, []byte(s), nil)
	if err2 != nil {
		er4 := fmt.Sprintf(err2.Error())
		derr := status.Errorf(4001002, er4)
		return "", derr
	}
	ct := hex.EncodeToString(ciphertext)

	return ct, nil
}

func HMAC512_Encrypt(secretMessage string, clientSecret string) (string, error) {
	hash := hmac.New(sha512.New, []byte(clientSecret))
	hash.Write([]byte(secretMessage))
	dhash := hex.EncodeToString(hash.Sum(nil))
	return dhash, nil
}

func GenHMAC512(method, path, body, clientSecret, token string) (string, error) {
	bmsg := []byte(body)
	hasher := sha256.New()
	hasher.Write(bmsg)
	dmsg := strings.ToLower(hex.EncodeToString(hasher.Sum(nil)))
	msg := method + ":" + path + ":" + token + ":" + dmsg
	fmt.Println("data: " + msg)
	signature, err4 := HMAC512_Encrypt(msg, clientSecret)
	if err4 != nil {
		fmt.Println(err4.Error())
		return "None", err4
	}

	return signature, nil
}
