package keycloakapi

import (
	"fmt"

	//"errors"
	"time"

	"github.com/aburavi/snaputils/proto/authv1"

	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type Attr struct {
	SrcRekening []string `json:"srcRekening,omitempty"`
	Max         []string `json:"max,omitempty"`
}

func GrpcCheckUriAccess(uri, token string) ([]string, error) {
	authgrpc := viper.GetString("URL_AUTH_BASE")
	conn, err := grpc.NewClient(authgrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4011302, er)
		return nil, derr
	}
	defer conn.Close()

	client := authv1.NewAuthV1Client(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err := client.GetResourceSetUriV1(ctx, &authv1.ResourceSetUriV1Request{Uri: uri, Token: token})
	if err != nil {
		derr := status.Errorf(4011301, "Access Token Invalid")
		fmt.Println("Error when callin resourceset uri: %s", derr)
		return nil, derr
	}

	fmt.Println("Response from Uri server: %s", response.ResourceId)

	return response.ResourceId, nil
}

func GrpcKeycloakResourceAttributes(resourcesetid string, token string) ([]string, []string, error) {
	authgrpc := viper.GetString("URL_AUTH_BASE")
	conn, err := grpc.NewClient(authgrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4011302, er)
		return nil, nil, derr
	}
	defer conn.Close()

	client := authv1.NewAuthV1Client(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err := client.GetResourceSetAttributeV1(ctx, &authv1.ResourceSetAttributeV1Request{ResourceId: resourcesetid, Token: token})
	if err != nil {
		derr := status.Errorf(4011301, "Access Token Invalid")
		fmt.Println("Error when callin resource attribute: %s", derr)
		return nil, nil, derr
	}
	fmt.Println("Response from Attributes server: %s", response)

	return response.Attributes.SrcRekening, response.Attributes.Max, nil
}
