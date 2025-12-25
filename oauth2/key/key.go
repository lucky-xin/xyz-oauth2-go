package key

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/lucky-xin/xyz-common-go/env"
	grpcconn "github.com/lucky-xin/xyz-oauth2-go/oauth2/grpc"
	"github.com/lucky-xin/xyz-oauth2-go/upms"
	"github.com/patrickmn/go-cache"
)

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

type TokenKey struct {
	Id  string `json:"id"`
	Key string `json:"key"`
	Alg string `json:"alg"`
}

type GrpcTokenKeySvc struct {
	expiresMs time.Duration
	client    upms.OAuth2SvcClient
}

func Create(expiresMs time.Duration) *GrpcTokenKeySvc {
	cc, err := grpcconn.GetConnection()
	if err != nil {
		log.Fatalf("ERROR: Failed to create gRPC connection: %v", err)
		return nil
	}
	return &GrpcTokenKeySvc{
		expiresMs: expiresMs,
		client:    upms.NewOAuth2SvcClient(cc),
	}
}

func CreateWithEnv() *GrpcTokenKeySvc {
	return Create(6 * time.Hour)
}

func (svc *GrpcTokenKeySvc) GetTokenKey() (byts []byte, err error) {
	// 优先从环境变量获取
	tk := env.GetString("OAUTH2_TOKEN_KEY", "")
	if tk != "" {
		byts = []byte(tk)
		return
	}

	cacheKey := "token_key"
	if tokenKey, exist := c.Get(cacheKey); !exist {
		mu.Lock()
		defer mu.Unlock()
		if tokenKey, exist = c.Get(cacheKey); exist {
			byts = tokenKey.([]byte)
			return
		}

		// 调用gRPC服务
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := svc.client.GetTokenKey(ctx, &upms.Empty{})
		if err != nil {
			return nil, err
		}

		// 直接使用key字段
		byts = resp.Key
		c.Set(cacheKey, byts, svc.expiresMs)
	} else {
		byts = tokenKey.([]byte)
	}
	return
}
