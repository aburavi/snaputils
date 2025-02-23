package storage

import (
	"fmt"
	"os"

	//"errors"
	"context"
	"time"

	//"strconv"
	//"strings"

	"github.com/aburavi/snaputils/proto/storage"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func GrpcExternalId(userid, refid, datetime string) (*storage.ExternalIdResponse, error) {
	var storegrpc = os.Getenv("URL_STORE_BASE")
	conn, err := grpc.NewClient(storegrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4051300, er)
		return nil, derr
	}
	defer conn.Close()

	client := storage.NewStorageClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()
	response, err3 := client.PostExternalId(ctx, &storage.ExternalIdRequest{ClientId: userid, ExternalId: refid, Datetime: datetime})
	if err3 != nil {
		er3 := fmt.Sprintf(err3.Error())
		derr := status.Errorf(4051300, er3)
		return nil, derr
	}

	fmt.Println("Response from ExternalId Storage Redis server: %s", response)

	return response, nil
}

func GrpcRefferenceNo(userid, refid, datetime string) (*storage.ReffNoResponse, error) {
	var storegrpc = os.Getenv("URL_STORE_BASE")
	conn, err := grpc.NewClient(storegrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4051300, er)
		return nil, derr
	}
	defer conn.Close()

	client := storage.NewStorageClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err3 := client.PostRefferenceNo(ctx, &storage.ReffNoRequest{ClientId: userid, ReffNo: refid, Datetime: datetime})
	if err3 != nil {
		er3 := fmt.Sprintf(err3.Error())
		derr := status.Errorf(4051300, er3)
		return nil, derr
	}

	fmt.Println("Response from RefferenceId Storage Redis server: %s", response)

	return response, nil
}

func GrpcSetTrxId(userid, orirefid, refid string) (*storage.TrxIdResponse, error) {
	var storegrpc = os.Getenv("URL_STORE_BASE")
	conn, err := grpc.NewClient(storegrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4051300, er)
		return nil, derr
	}
	defer conn.Close()

	client := storage.NewStorageClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err3 := client.PostTrxId(ctx, &storage.TrxIdRequest{ClientId: userid, OriginalReffNo: orirefid, ReffNo: refid})
	if err3 != nil {
		er3 := fmt.Sprintf(err3.Error())
		derr := status.Errorf(4051300, er3)
		return nil, derr
	}

	fmt.Println("Response from TrxId Storage Redis server: %s", response)

	return response, nil
}

func GrpcGetTrxId(userid, orirefid string) (*storage.TrxIdResponse, error) {
	var storegrpc = os.Getenv("URL_STORE_BASE")
	conn, err := grpc.NewClient(storegrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4051300, er)
		return nil, derr
	}
	defer conn.Close()

	client := storage.NewStorageClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	response, err3 := client.GetTrxId(ctx, &storage.TrxIdRequest{ClientId: userid, OriginalReffNo: orirefid})
	if err3 != nil {
		er3 := fmt.Sprintf(err3.Error())
		derr := status.Errorf(4051300, er3)
		return nil, derr
	}

	fmt.Println("Response from TrxId Storage Redis server: %s", response)

	return response, nil
}
