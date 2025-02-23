package ratelimiter

import (
	"fmt"
	"os"

	//"errors"
	"context"
	"strconv"
	"time"

	//"strings"

	"github.com/aburavi/snaputils/proto/ratelimiter"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func GrpcPushSlidingWindow(userid, max string) (*ratelimiter.RatelimiterPushSlidingWindowResponse, error) {
	var ratelimitergrpc = os.Getenv("URL_STORE_BASE")
	conn, err := grpc.NewClient(ratelimitergrpc, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		er := fmt.Sprintf("fail to dial: %v", err)
		derr := status.Errorf(4051200, er)
		return nil, derr
	}
	defer conn.Close()

	client := ratelimiter.NewRatelimiterClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	//defer cancel()

	dmax, err2 := strconv.ParseInt(max, 10, 64)
	if err2 != nil {
		er2 := fmt.Sprintf(err2.Error())
		derr := status.Errorf(4051200, er2)
		return nil, derr

	}

	response, err3 := client.PushSlidingWindow(ctx, &ratelimiter.RatelimiterPushSlidingWindowRequest{ClientId: userid, Max: dmax})
	if err3 != nil {
		er3 := fmt.Sprintf(err3.Error())
		derr := status.Errorf(4051200, er3)
		return nil, derr
	}

	fmt.Println("Response from Ratelimiter server: %s", response)

	return response, nil
}
