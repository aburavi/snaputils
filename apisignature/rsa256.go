package apisignature

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/aburavi/snaputils/async"
	"github.com/aburavi/snaputils/proto/backend"

	"github.com/spf13/viper"

	"github.com/valyala/fasthttp"
	"google.golang.org/grpc/credentials/insecure"
)

func getPrivateKeyGrpc(clientId string) (string, error) {
	backendgrpc := viper.GetString("URL_BACKEND_BASE")
	conn, err := grpc.NewClient(backendgrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	backendgrpc := viper.GetString("URL_BACKEND_BASE")
	conn, err := grpc.NewClient(backendgrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	var backendhttp = os.Getenv("URL_BACKEND_BASE")
	var cryptoToken = os.Getenv("CRYPTO_TOKEN")
	var uri = backendhttp + "/api/v1/basecrypto/apps/key/" + clientId

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

func CekTokenExist(clientid string) (string, error) {
	var future1 async.Future
	future1 = async.Exec(func() (interface{}, error) {
		data_clientkey, err1 := getPublicKeyGrpc(clientid)
		return data_clientkey, err1
	})

	val, err2 := future1.Await()
	if err2 != nil {
		er1 := fmt.Sprintf("service hit failed: %s\n", err2)
		derr := status.Errorf(4001102, er1)
		return "None", derr
	}

	secret := strings.Split(val.(string), "|")

	return secret[0], nil
}

func getUserKeyGrpc(user_id string) (string, error) {
	backendgrpc := viper.GetString("URL_BACKEND_BASE")
	conn, err := grpc.Dial(backendgrpc, grpc.WithInsecure())
	if err != nil {
		er1 := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4001102, er1)
		return "None", derr
	}
	defer conn.Close()

	client := backend.NewBackendClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err := client.GetUserKey(ctx, &backend.UserKeyRequest{UserId: user_id})
	if err != nil {
		er2 := fmt.Sprintf("Error when callin privatekey: %s", err)
		derr := status.Errorf(4001102, er2)
		return "None", derr
	}
	fmt.Println("Response from server: %s", response)

	return response.ClientSecret + "|" + response.PrivateKey, nil
}
