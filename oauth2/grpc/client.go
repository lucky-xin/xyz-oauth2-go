package grpc

import (
	"log"
	"sync"
	"time"

	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/lucky-xin/xyz-oauth2-go/upms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	maxMessageSize = 50 * 1024 * 1024 // 50MB
)

var (
	conn *grpc.ClientConn
	mu   sync.RWMutex
)

type Client struct {
	conn                          *grpc.ClientConn
	oauth2SvcCli                  upms.OAuth2SvcClient
	userDetailsSvcCli             upms.UserDetailsSvcClient
	clientDetailsSvcCli           upms.ClientDetailsSvcClient
	encryptionConfigDetailsSvcCli upms.EncryptionConfigDetailsSvcClient
	debug                         bool
}

// GetConnection 获取gRPC连接
func GetConnection() (cc *grpc.ClientConn, err error) {
	if conn != nil {
		return conn, nil
	}

	mu.Lock()
	defer mu.Unlock()

	if conn != nil {
		return conn, nil
	}

	// 从环境变量获取gRPC服务地址
	grpcAddr := env.GetString("OAUTH2_GRPC_ADDR", "127.0.0.1:9090")
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMessageSize),
			grpc.MaxCallSendMsgSize(maxMessageSize),
		),
	}

	startTime := time.Now()
	conn, err = grpc.NewClient(grpcAddr, opts...)
	if err != nil {
		log.Printf("ERROR: Failed to connect to DocReader service: %v", err)
		return nil, err
	}
	log.Printf("INFO: Successfully connected to DocReader service in %v", time.Since(startTime))

	// 创建gRPC连接
	conn, err = grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// CloseConnection 关闭gRPC连接
func CloseConnection() error {
	mu.Lock()
	defer mu.Unlock()

	if conn != nil {
		err := conn.Close()
		conn = nil
		return err
	}
	return nil
}
