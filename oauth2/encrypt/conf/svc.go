package conf

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/lucky-xin/xyz-oauth2-go/oauth2"
	grpcconn "github.com/lucky-xin/xyz-oauth2-go/oauth2/grpc"
	"github.com/lucky-xin/xyz-oauth2-go/upms"
	"github.com/patrickmn/go-cache"
)

type GrpcEncryptionConfigSvc struct {
	c      *cache.Cache
	mua    sync.RWMutex
	client upms.EncryptionConfigDetailsSvcClient
}

func Create(expireMs, cleanupMs time.Duration) *GrpcEncryptionConfigSvc {
	cc, err := grpcconn.GetConnection()
	if err != nil {
		log.Fatalf("ERROR: Failed to create gRPC connection: %v", err)
		return nil
	}
	client := upms.NewEncryptionConfigDetailsSvcClient(cc)
	return &GrpcEncryptionConfigSvc{
		c:      cache.New(expireMs, cleanupMs),
		client: client,
	}
}

func CreateWithEnv() *GrpcEncryptionConfigSvc {
	// 默认6小时过期和清理
	return Create(6*time.Hour, 6*time.Hour)
}

func (svc *GrpcEncryptionConfigSvc) GetEncryptInf(appId string) (*oauth2.EncryptionInf, error) {
	key := "app_id:" + appId
	if val, b := svc.c.Get(key); b {
		s := val.(*oauth2.EncryptionInf)
		return s, nil
	}

	svc.mua.Lock()
	defer svc.mua.Unlock()
	if val, b := svc.c.Get(key); b {
		s := val.(*oauth2.EncryptionInf)
		return s, nil
	}

	// 调用gRPC服务
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := svc.client.LoadByAppId(ctx, &upms.LoadByAppIdReq{
		AppId: appId,
	})
	if err != nil {
		return nil, err
	}

	// 转换为EncryptionInf
	conf := convertToEncryptionInf(resp)
	svc.c.Set(key, conf, 24*time.Hour)
	return conf, nil
}

// convertToEncryptionInf 将gRPC的EncryptionConfigDetails转换为oauth2.EncryptionInf
func convertToEncryptionInf(grpcConf *upms.EncryptionConfigDetails) *oauth2.EncryptionInf {
	if grpcConf == nil {
		return nil
	}

	return &oauth2.EncryptionInf{
		AppId:         grpcConf.AppId,
		AppSecret:     grpcConf.AppSecret,
		SM2PrivateKey: grpcConf.Sm2PrivateKey,
		SM2PublicKey:  grpcConf.Sm2PublicKey,
		TenantId:      0, // TenantId字段在gRPC response中没有对应字段
		Username:      grpcConf.Username,
	}
}
