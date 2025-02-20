package apisignature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"snaputils/proto/backend"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

var publicKey = []byte(`-----BEGIN PUBLIC KEY-----
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
func RSA_OAEP_Decrypt(msg, sig, clientId string, mode int) (string, bool, error) {
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

func getPrivateKeyGrpc(clientId string) (string, error) {
	conn, err := grpc.NewClient("backend.snap-aspi:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er1 := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4001102, er1)
		return "None", derr
	}
	defer conn.Close()

	client := backend.NewBackendClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err := client.GetClientKey(ctx, &backend.ClientKeyRequest{ClientId: clientId})
	if err != nil {
		er2 := fmt.Sprintf("Error when callin privatekey: %s", err)
		derr := status.Errorf(4001102, er2)
		return "None", derr
	}
	fmt.Println("Response from server: %s", response.PrivateKey)

	return response.ClientSecret + "|" + response.PrivateKey, nil
}

func getPrivateKeyHttp(clientId string) (string, error) {
	var base = os.Getenv("URL_BACKEND_BASE")
	var cryptoToken = os.Getenv("CRYPTO_TOKEN")
	var uri = base + "/api/v1/basecrypto/apps/client/" + clientId

	type Key struct {
		ClientSecret string `json:"client_secret, omitempty"`
		PrivateKey   string `json:"private_key, omitempty"`
	}

	type TokenV1Response struct {
		Data Key `json:"data, omitempty"`
	}
	var p TokenV1Response

	dreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dreq)
	dreq.SetRequestURI(uri)
	dreq.Header.SetMethod("GET")
	dreq.Header.Set("Content-Type", "application/json")
	dreq.Header.Set("Authorization", "Bearer "+cryptoToken)
	dresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(dresp)
	if err := fasthttp.Do(dreq, dresp); err != nil {
		fmt.Printf("Client get failed: %s\n", err)
		return "None", nil
	}
	b := dresp.Body()
	if dresp.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("load list failed code=%d. [err=%v]\n", dresp.StatusCode(), string(b))
		return "None", nil
	}

	err1 := json.Unmarshal(b, &p)
	if err1 != nil {
		fmt.Printf("Decode data payload failed: %s\n", err1)
		return "None", nil
	}
	return p.Data.ClientSecret + "|" + p.Data.PrivateKey, nil
}

func getPublicKeyGrpc(clientId string) (string, error) {
	conn, err := grpc.NewClient("backend.snap-aspi:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er1 := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4001102, er1)
		return "None", derr
	}
	defer conn.Close()

	client := backend.NewBackendClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err1 := client.GetClientKey(ctx, &backend.ClientKeyRequest{ClientId: clientId})
	if err1 != nil {
		er2 := fmt.Sprintf("Error when callin publickey: %s", err1)
		derr := status.Errorf(4001102, er2)
		return "None", derr
	}
	dstring := response.ClientSecret + "|" + response.PublicKey
	fmt.Println("Response from server1: ", dstring)

	return dstring, nil
}

func getPublicKeyHttp(clientId string) (string, error) {
	var base = os.Getenv("URL_BACKEND_BASE")
	var cryptoToken = os.Getenv("CRYPTO_TOKEN")
	var uri = base + "/api/v1/basecrypto/apps/key/" + clientId

	type Key struct {
		ClientSecret string `json:"client_secret, omitempty"`
		PublicKey    string `json:"private_key, omitempty"`
	}

	type TokenV1Response struct {
		Data Key `json:"data, omitempty"`
	}
	var p TokenV1Response

	dreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dreq)
	dreq.SetRequestURI(uri)
	dreq.Header.SetMethod("GET")
	dreq.Header.Set("Content-Type", "application/json")
	dreq.Header.Set("Authorization", "Bearer "+cryptoToken)
	dresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(dresp)
	if err := fasthttp.Do(dreq, dresp); err != nil {
		fmt.Printf("Client get failed: %s\n", err)
		return "None", nil
	}
	b := dresp.Body()
	if dresp.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("load list failed code=%d. [err=%v]\n", dresp.StatusCode(), string(b))
		return "None", nil
	}

	err1 := json.Unmarshal(b, &p)
	if err1 != nil {
		fmt.Printf("Decode data payload failed: %s\n", err1)
		return "None", nil
	}
	return p.Data.ClientSecret + "|" + p.Data.PublicKey, nil
}
