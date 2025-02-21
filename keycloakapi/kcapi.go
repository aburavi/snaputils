package keycloakapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/aburavi/snaputils/apisignature"
	"github.com/aburavi/snaputils/proto/authv1"

	"github.com/valyala/fasthttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ResourceSet struct {
	Uris []string `json:"uris,omitempty"`
}

func KeycloakAuthV1(ctx context.Context, req *authv1.AuthV1Request) (*authv1.AuthV1Response, error) {
	var base = os.Getenv("URL_KEYCLOAK_BASE")
	var uri = base + "/realms/openapi/protocol/openid-connect/token"

	type TokenV1Response struct {
		AccessToken      string `json:"access_token, omitempty"`
		ExpiresIn        int32  `json:"expires_in, omitempty"`
		RefreshExpiresIn int32  `json:"refresh_expires_in, omitempty"`
		TokenType        string `json:"token_type, omitempty"`
		NotBeforePolicy  int32  `json:"not-before-policy, omitempty"`
		Scope            string `json:"scope, omitempty"`
	}

	rspdata := TokenV1Response{}
	protosdata := authv1.AuthV1Response{}
	xUrlMethod := ""
	xUrlPath := ""
	contentType := ""
	channelId := ""
	xExternalId := ""
	xPartnerId := ""
	origin := ""
	dsig := ""
	clientId := ""
	xTimestamp := ""

	// Read metadata from client.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.DataLoss, "UnaryEcho: failed to get metadata")
	}
	if dheader1, ok := md["x-url-method"]; ok {
		for _, e := range dheader1 {
			xUrlMethod = e
		}
	}
	if dheader2, ok := md["x-url-path"]; ok {
		for _, e := range dheader2 {
			xUrlPath = e
		}
	}
	if dheader3, ok := md["content-type"]; ok {
		for _, e := range dheader3 {
			contentType = e
		}
	}
	if dheader4, ok := md["x-timestamp"]; ok {
		for _, e := range dheader4 {
			xTimestamp = e
		}
	}
	if dheader5, ok := md["x-client-key"]; ok {
		for _, e := range dheader5 {
			clientId = e
		}
	}
	if dheader6, ok := md["x-signature"]; ok {
		for _, e := range dheader6 {
			dsig = e
		}
	}
	if dheader7, ok := md["origin"]; ok {
		for _, e := range dheader7 {
			origin = e
		}
	}
	if dheader8, ok := md["x-partner-id"]; ok {
		for _, e := range dheader8 {
			xPartnerId = e
		}
	}
	if dheader9, ok := md["x-external-id"]; ok {
		for _, e := range dheader9 {
			xExternalId = e
		}
	}
	if dheader10, ok := md["channel-id"]; ok {
		for _, e := range dheader10 {
			channelId = e
		}
	}

	dmsg := clientId + "|" + xTimestamp
	sig, valid, err := apisignature.RSA_OAEP_Decrypt_Http(dmsg, dsig, clientId, 0)
	if (err != nil) && (valid == false) {
		fmt.Printf("Signature failed: %s\n", err)
		protosdata.ResponseCode = "4017300"
		protosdata.ResponseMessage = "Unauthorized. Signature failed"
		return &protosdata, nil
	}

	fmt.Println(sig)
	dtsig := strings.Split(sig, "|")
	//sigvalid := sig
	clientSecret := dtsig[0]
	//pubkey := dtsig[1]

	fmt.Println(xUrlMethod)
	fmt.Println(xUrlPath)
	fmt.Println(clientId)
	fmt.Println(clientSecret)
	fmt.Println(contentType)
	fmt.Println(xTimestamp)
	fmt.Println(origin)
	fmt.Println(xPartnerId)
	fmt.Println(xExternalId)
	fmt.Println(channelId)

	dreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dreq)
	dreq.SetRequestURI(uri)
	dreq.Header.SetMethod("POST")
	dreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(dresp)

	reqdata := url.Values{}
	reqdata.Set("client_id", clientId)
	reqdata.Set("client_secret", clientSecret)
	reqdata.Set("grant_type", req.GrantType)
	reqdata.Set("scope", "offline_access")

	dreq.SetBodyString(reqdata.Encode())

	if err := fasthttp.Do(dreq, dresp); err != nil {
		fmt.Printf("Client API auth get failed: %s\n", err)
		protosdata.ResponseCode = "5007302"
		protosdata.ResponseMessage = "External Server Error: Client API auth get failed"
		return &protosdata, nil
	}

	b := dresp.Body()
	if dresp.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("load list auth failed code=%d. [err=%v]\n", dresp.StatusCode(), string(b))
		protosdata.ResponseCode = "5007302"
		protosdata.ResponseMessage = fmt.Sprintf("External Server Error. %s", strconv.Itoa(dresp.StatusCode())+", "+string(b))
		return &protosdata, nil
	}

	err1 := json.Unmarshal(b, &rspdata)
	if err1 != nil {
		fmt.Printf("Decode auth data payload failed: %s\n", err1)
		protosdata.ResponseCode = "5007302"
		protosdata.ResponseMessage = fmt.Sprintf("External Server Error. %s", err1)
		return &protosdata, nil
	}

	protosdata.ResponseCode = "2007300"
	protosdata.ResponseMessage = "Successful"
	protosdata.AccessToken = rspdata.AccessToken
	protosdata.TokenType = rspdata.TokenType
	protosdata.ExpiresIn = rspdata.ExpiresIn
	return &protosdata, nil
}

func KeycloakRefreshAuthV1(ctx context.Context, req *authv1.RefreshAuthV1Request) (*authv1.RefreshAuthV1Response, error) {
	var base = os.Getenv("URL_KEYCLOAK_BASE")
	var uri = base + "/realms/openapi/protocol/openid-connect/token"

	type TokenV1Response struct {
		AccessToken      string `json:"access_token, omitempty"`
		RefreshToken     string `json:"refresh_token, omitempty"`
		ExpiresIn        int32  `json:"expires_in, omitempty"`
		RefreshExpiresIn int32  `json:"refresh_expires_in, omitempty"`
		TokenType        string `json:"token_type, omitempty"`
		NotBeforePolicy  int32  `json:"not-before-policy, omitempty"`
		Scope            string `json:"scope, omitempty"`
	}

	rspdata := TokenV1Response{}
	protosdata := authv1.RefreshAuthV1Response{}
	xUrlMethod := ""
	xUrlPath := ""
	contentType := ""
	channelId := ""
	xExternalId := ""
	xPartnerId := ""
	origin := ""
	dsig := ""
	clientId := ""
	xTimestamp := ""

	// Read metadata from client.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.DataLoss, "UnaryEcho: failed to get metadata")
	}
	if dheader1, ok := md["x-url-method"]; ok {
		for _, e := range dheader1 {
			xUrlMethod = e
		}
	}
	if dheader2, ok := md["x-url-path"]; ok {
		for _, e := range dheader2 {
			xUrlPath = e
		}
	}
	if dheader3, ok := md["content-type"]; ok {
		for _, e := range dheader3 {
			contentType = e
		}
	}
	if dheader4, ok := md["x-timestamp"]; ok {
		for _, e := range dheader4 {
			xTimestamp = e
		}
	}
	if dheader5, ok := md["x-client-key"]; ok {
		for _, e := range dheader5 {
			clientId = e
		}
	}
	if dheader6, ok := md["x-signature"]; ok {
		for _, e := range dheader6 {
			dsig = e
		}
	}
	if dheader7, ok := md["origin"]; ok {
		for _, e := range dheader7 {
			origin = e
		}
	}
	if dheader8, ok := md["x-partner-id"]; ok {
		for _, e := range dheader8 {
			xPartnerId = e
		}
	}
	if dheader9, ok := md["x-external-id"]; ok {
		for _, e := range dheader9 {
			xExternalId = e
		}
	}
	if dheader10, ok := md["channel-id"]; ok {
		for _, e := range dheader10 {
			channelId = e
		}
	}
	dmsg := clientId + "|" + xTimestamp
	sig, valid, err := apisignature.RSA_OAEP_Decrypt_Http(dmsg, dsig, clientId, 0)
	if (err != nil) && (valid == false) {
		fmt.Printf("Signature refresh get failed: %s\n", sig)
		protosdata.ResponseCode = "99"
		protosdata.ResponseMessage = "Signature refresh get failed"
		return &protosdata, err
	}

	fmt.Println(sig)
	dtsig := strings.Split(sig, "|")
	//sigvalid := sig
	clientSecret := dtsig[0]
	//pubkey := dtsig[1]

	fmt.Println(xUrlMethod)
	fmt.Println(xUrlPath)
	fmt.Println(clientId)
	fmt.Println(clientSecret)
	fmt.Println(contentType)
	fmt.Println(xTimestamp)
	fmt.Println(origin)
	fmt.Println(xPartnerId)
	fmt.Println(xExternalId)
	fmt.Println(channelId)

	dreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dreq)
	dreq.SetRequestURI(uri)
	dreq.Header.SetMethod("POST")
	dreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(dresp)

	reqdata := url.Values{}
	reqdata.Set("client_id", clientId)
	reqdata.Set("client_secret", clientSecret)
	reqdata.Set("refresh_token", req.RefreshToken)
	reqdata.Set("grant_type", "refresh_token")
	reqdata.Set("scope", "offline_access")

	dreq.SetBodyString(reqdata.Encode())

	if err := fasthttp.Do(dreq, dresp); err != nil {
		fmt.Printf("Client API auth get failed: %s\n", err)
		protosdata.ResponseCode = "99"
		protosdata.ResponseMessage = "Client API auth get failed"
		return &protosdata, err
	}

	b := dresp.Body()
	if dresp.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("load list auth failed code=%d. [err=%v]\n", dresp.StatusCode(), string(b))
		protosdata.ResponseCode = "99"
		protosdata.ResponseMessage = "Load list auh failed"
		return &protosdata, errors.New("code:" + strconv.Itoa(dresp.StatusCode()) + ", " + string(b))
	}

	err1 := json.Unmarshal(b, &rspdata)
	if err1 != nil {
		fmt.Printf("Decode auth data payload failed: %s\n", err1)
		protosdata.ResponseCode = "99"
		protosdata.ResponseMessage = "Decode auth data payload failed"
		return &protosdata, err1
	}

	protosdata.ResponseCode = "00"
	protosdata.ResponseMessage = "Success"
	protosdata.AccessToken = rspdata.AccessToken
	protosdata.RefreshToken = rspdata.RefreshToken
	protosdata.TokenType = rspdata.TokenType
	protosdata.ExpiresIn = rspdata.ExpiresIn
	return &protosdata, nil
}

func KeycloakAuthV1Http(req *http.Request) (*authv1.AuthV1Response, error) {
	var base = os.Getenv("URL_KEYCLOAK_BASE")
	var uri = base + "/realms/openapi/protocol/openid-connect/token"

	type TokenV1Response struct {
		AccessToken      string `json:"access_token, omitempty"`
		ExpiresIn        int32  `json:"expires_in, omitempty"`
		RefreshExpiresIn int32  `json:"refresh_expires_in, omitempty"`
		TokenType        string `json:"token_type, omitempty"`
		NotBeforePolicy  int32  `json:"not-before-policy, omitempty"`
		Scope            string `json:"scope, omitempty"`
	}

	rspdata := TokenV1Response{}
	protosdata := authv1.AuthV1Response{}
	contentType := req.Header.Get("Content-type")
	channelId := req.Header.Get("CHANNEL-ID")
	xExternalId := req.Header.Get("X-External-ID")
	xPartnerId := req.Header.Get("X-PARTNER-ID")
	origin := req.Header.Get("ORIGIN")
	dsig := req.Header.Get("X-SIGNATURE")
	clientId := req.Header.Get("X-CLIENT-KEY")
	xTimestamp := req.Header.Get("X-TIMESTAMP")

	mesg := clientId + "|" + xTimestamp

	sig, valid, err := apisignature.RSA_OAEP_Decrypt_Http(mesg, dsig, clientId, 1)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println(sig)
	dtsig := strings.Split(sig, "|")
	//sigvalid := sig
	clientSecret := dtsig[0]
	//pubkey := dtsig[1]

	type Grant struct {
		GrantType string `json:"grant_type, omitempty"`
	}
	var p Grant
	derr := json.NewDecoder(req.Body).Decode(&p)
	if derr != nil {
		fmt.Println(derr.Error())
	}

	fmt.Println(valid)
	fmt.Println(clientSecret)
	fmt.Println(contentType)
	fmt.Println(xTimestamp)
	fmt.Println(origin)
	fmt.Println(xPartnerId)
	fmt.Println(xExternalId)
	fmt.Println(channelId)

	dreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dreq)
	dreq.SetRequestURI(uri)
	dreq.Header.SetMethod("POST")
	dreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(dresp)

	reqdata := url.Values{}
	reqdata.Set("client_id", clientId)
	reqdata.Set("client_secret", clientSecret)
	reqdata.Set("grant_type", p.GrantType)
	reqdata.Set("scope", "offline_access")

	dreq.SetBodyString(reqdata.Encode())

	if err := fasthttp.Do(dreq, dresp); err != nil {
		fmt.Printf("Client API auth get failed: %s\n", err)
		protosdata.ResponseCode = "99"
		protosdata.ResponseMessage = "Client API auth get failed"
		return &protosdata, err
	}

	b := dresp.Body()
	if dresp.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("load list auth failed code=%d. [err=%v]\n", dresp.StatusCode(), string(b))
		protosdata.ResponseCode = "99"
		protosdata.ResponseMessage = "Load list auh failed"
		return &protosdata, errors.New("code:" + strconv.Itoa(dresp.StatusCode()) + ", " + string(b))
	}

	err1 := json.Unmarshal(b, &rspdata)
	if err1 != nil {
		fmt.Printf("Decode auth data payload failed: %s\n", err1)
		protosdata.ResponseCode = "99"
		protosdata.ResponseMessage = "Decode auth data payload failed"
		return &protosdata, err1
	}

	protosdata.ResponseCode = "00"
	protosdata.ResponseMessage = "Success"
	protosdata.AccessToken = rspdata.AccessToken
	protosdata.TokenType = rspdata.TokenType
	protosdata.ExpiresIn = rspdata.ExpiresIn
	return &protosdata, nil
}

func KeycloakCheckUriV1Access(ctx context.Context, req *authv1.ResourceSetUriV1Request) (*authv1.ResourceSetUriV1Response, error) {
	var base = os.Getenv("URL_KEYCLOAK_BASE")
	var stype = os.Getenv("TYPE")
	var kcurl = base + "/realms/openapi/authz/protection/resource_set?uri=/" + stype + req.Uri
	var data = authv1.ResourceSetUriV1Response{}
	fmt.Printf(kcurl)

	dreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dreq)
	dreq.SetRequestURI(kcurl)
	dreq.Header.SetMethod("GET")
	dreq.Header.Set("Content-Type", "application/json")
	dreq.Header.Set("Authorization", req.Token)
	dresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(dresp)
	if err2 := fasthttp.Do(dreq, dresp); err2 != nil {
		fmt.Printf("Client get failed: %s\n", err2)
		return nil, err2
	}
	b := dresp.Body()
	if dresp.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("load list failed code=%d. [err=%v]\n", dresp.StatusCode(), string(b))
		return nil, errors.New("error code: " + string(dresp.StatusCode()))
	}

	var ddata []string
	err3 := json.Unmarshal(b, &ddata)
	if err3 != nil {
		fmt.Printf("Decode data payload failed: %s\n", err3)
		return nil, err3
	}

	//if len(b) != 1 {
	//	return nil, errors.New("uri not match, deny")
	//}
	//fmt.Printf("KeycloakCheckUriV1Access: "+string(b))
	data.ResourceId = ddata
	return &data, nil
}

func KeycloakCheckAttributeV1Access(ctx context.Context, req *authv1.ResourceSetAttributeV1Request) (*authv1.ResourceSetAttributeV1Response, error) {
	var base = os.Getenv("URL_KEYCLOAK_BASE")
	var kcurl = base + "/realms/openapi/authz/protection/resource_set/" + req.ResourceId
	var data = authv1.ResourceSetAttributeV1Response{}

	dreq := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(dreq)
	dreq.SetRequestURI(kcurl)
	dreq.Header.SetMethod("GET")
	dreq.Header.Set("Content-Type", "application/json")
	dreq.Header.Set("Authorization", req.Token)
	dresp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(dresp)
	if err := fasthttp.Do(dreq, dresp); err != nil {
		fmt.Printf("Client get failed: %s\n", err)
		return nil, err
	}
	b := dresp.Body()
	if dresp.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("load list failed code=%d. [err=%v]\n", dresp.StatusCode(), string(b))
		return nil, errors.New("error code: " + string(dresp.StatusCode()))
	}
	err1 := json.Unmarshal(b, &data)
	if err1 != nil {
		fmt.Printf("Decode data payload failed: %s\n", err1)
		return nil, err1
	}

	return &data, nil
}
