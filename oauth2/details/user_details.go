package details

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lucky-xin/xyz-oauth2-go/oauth2"
	grpcconn "github.com/lucky-xin/xyz-oauth2-go/oauth2/grpc"
	"github.com/lucky-xin/xyz-oauth2-go/upms"
	"github.com/patrickmn/go-cache"
)

var (
	c  = cache.New(24*time.Hour, 24*time.Hour)
	mu sync.RWMutex
)

type GrpcUserDetailsSvc struct {
	expiresMs time.Duration
	client    upms.UserDetailsSvcClient
}

func Create(expiresMs time.Duration) *GrpcUserDetailsSvc {
	cc, err := grpcconn.GetConnection()
	if err != nil {
		log.Fatalf("ERROR: Failed to create gRPC connection: %v", err)
		return nil
	}
	return &GrpcUserDetailsSvc{expiresMs: expiresMs, client: upms.NewUserDetailsSvcClient(cc)}
}

func CreateWithEnv() *GrpcUserDetailsSvc {
	// 默认12小时过期
	return Create(12 * time.Hour)
}

func (svc *GrpcUserDetailsSvc) Get(username string) (details *oauth2.UserDetails, err error) {
	cacheKey := "user:" + username
	if cached, exist := c.Get(cacheKey); !exist {
		mu.Lock()
		defer mu.Unlock()
		if cached, exist = c.Get(cacheKey); exist {
			details = cached.(*oauth2.UserDetails)
			return
		}
		// 调用gRPC服务
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := svc.client.LoadDetailsByUserName(ctx, &upms.LoadDetailsByUserNameReq{
			UserName: username,
		})
		if err != nil {
			return nil, err
		}

		// 转换为UserDetails
		details = convertToUserDetails(resp)
		c.Set(cacheKey, details, svc.expiresMs)
	} else {
		details = cached.(*oauth2.UserDetails)
	}
	return
}

// convertToUserDetails 将gRPC的OAuth2UserDetails转换为oauth2.UserDetails
func convertToUserDetails(grpcDetails *upms.OAuth2UserDetails) *oauth2.UserDetails {
	if grpcDetails == nil {
		return nil
	}

	details := &oauth2.UserDetails{
		Id:        grpcDetails.Id,
		TenantId:  int32(grpcDetails.TenantId),
		Username:  grpcDetails.Username,
		Alias:     grpcDetails.Nickname,
		DeptId:    grpcDetails.DeptId,
		RoleIds:   grpcDetails.RoleIds,
		RoleTypes: convertInt32ToInt64(grpcDetails.RoleTypes),
	}

	// 转换权限列表
	if len(grpcDetails.Authorities) > 0 {
		details.Authorities = make([]struct {
			Authorities int64  `json:"authorities"`
			Authority   string `json:"authority"`
		}, len(grpcDetails.Authorities))

		for i, auth := range grpcDetails.Authorities {
			details.Authorities[i].Authorities = auth.Authorities
			details.Authorities[i].Authority = auth.Permission
		}
	}

	// 设置JWT时间字段（如果需要）
	now := time.Now()
	details.IssuedAt = jwt.NewNumericDate(now)
	details.NotBefore = jwt.NewNumericDate(now)
	details.ExpiresAt = jwt.NewNumericDate(now.Add(24 * time.Hour))

	return details
}

// convertInt32ToInt64 转换int32数组为int64数组
func convertInt32ToInt64(int32Slice []int32) []int64 {
	int64Slice := make([]int64, len(int32Slice))
	for i, v := range int32Slice {
		int64Slice[i] = int64(v)
	}
	return int64Slice
}
