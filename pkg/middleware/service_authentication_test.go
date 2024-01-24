package middleware

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/kyamalabs/auth/internal/api/middleware"
	mockcache "github.com/kyamalabs/auth/internal/cache/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestAuthenticateService(t *testing.T) {
	oneMinuteAgo := time.Now().UTC().Add(-1 * serviceAuthenticationPayloadDuration)
	oneMinuteAgoUTCMillis := oneMinuteAgo.UnixNano() / int64(time.Millisecond)
	currentTimeUTCMillis := time.Now().UTC().UnixNano() / int64(time.Millisecond)

	validPrivateKeyPEM := "MHcCAQEEINIZr7eRHNKIo+kqyLU5j8Y3mRmfn+5k2OY685DzM1MOoAoGCCqGSM49AwEHoUQDQgAEkcpsUaeko+BLe9sutR3FRCIQPBwlRU9UN2/69Q4RLb8upVzVcK+22dEJtvVzhu3bl1hgPk3HLIYPrtuLqKOQbw=="
	validPayload, err := GenerateServiceAuthenticationPayload("UsERs", []string{validPrivateKeyPEM})
	require.NoError(t, err)
	require.NotEmpty(t, validPayload)

	testCases := []struct {
		name                  string
		inputContext          context.Context
		expectedResultContext context.Context
		buildStubs            func(cache *mockcache.MockCache)
	}{
		{
			name:                  "successfully authenticates service",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload),
			expectedResultContext: context.WithValue(context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload), middleware.AuthenticatedService, "users"),
			buildStubs: func(cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil, nil)

				cache.EXPECT().
					Set(gomock.Any(), gomock.Any(), gomock.Any(), serviceAuthenticationPayloadDuration).
					Times(1).
					Return(nil)
			},
		},
		{
			name:                  "input context lacks service_authentication value",
			inputContext:          context.Background(),
			expectedResultContext: context.Background(),
			buildStubs: func(cache *mockcache.MockCache) {
			},
		},
		{
			name:                  "invalid service authentication payload",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, "invalid.payload"),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, "invalid.payload"),
			buildStubs: func(cache *mockcache.MockCache) {
			},
		},
		{
			name:                  "invalid service authentication request timestamp",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, "users.a.nPLZLG2JNI.dummybase64signature/+=="),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, "users.a.nPLZLG2JNI.dummybase64signature/+=="),
			buildStubs: func(cache *mockcache.MockCache) {
			},
		},
		{
			name:                  "service name not provided",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, ".1.nPLZLG2JNI.dummybase64signature/+=="),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, ".1.nPLZLG2JNI.dummybase64signature/+=="),
			buildStubs: func(cache *mockcache.MockCache) {
			},
		},
		{
			name:                  "expired service authentication payload",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, fmt.Sprintf("users.%d.nPLZLG2JNI.dummybase64signature/+==", oneMinuteAgoUTCMillis)),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, fmt.Sprintf("users.%d.nPLZLG2JNI.dummybase64signature/+==", oneMinuteAgoUTCMillis)),
			buildStubs: func(cache *mockcache.MockCache) {
			},
		},
		{
			name:                  "invalid service authentication nonce",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, fmt.Sprintf("users.%d.AbC456789.dummybase64signature/+==", currentTimeUTCMillis)),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, fmt.Sprintf("users.%d.AbC456789.dummybase64signature/+==", currentTimeUTCMillis)),
			buildStubs: func(cache *mockcache.MockCache) {
			},
		},
		{
			name:                  "invalid service authentication signature",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, fmt.Sprintf("users.%d.nPLZLG2JNI.invalidSignature/+==", currentTimeUTCMillis)),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, fmt.Sprintf("users.%d.nPLZLG2JNI.invalidSignature/+==", currentTimeUTCMillis)),
			buildStubs: func(cache *mockcache.MockCache) {
			},
		},
		{
			name:                  "service authentication signature exists in cache",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload),
			buildStubs: func(cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return("some-value", nil)
			},
		},
		{
			name:                  "cache Get() throws an error",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload),
			buildStubs: func(cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil, errors.New("some cache error"))
			},
		},
		{
			name:                  "cache Set() throws an error",
			inputContext:          context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload),
			expectedResultContext: context.WithValue(context.Background(), middleware.ServiceAuthentication, validPayload),
			buildStubs: func(cache *mockcache.MockCache) {
				cache.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Times(1).
					Return(nil, nil)

				cache.EXPECT().
					Set(gomock.Any(), gomock.Any(), gomock.Any(), serviceAuthenticationPayloadDuration).
					Times(1).
					Return(errors.New("some cache error"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			crtl := gomock.NewController(t)
			defer crtl.Finish()

			cache := mockcache.NewMockCache(crtl)
			tc.buildStubs(cache)

			config := &AuthenticateServiceConfig{
				Cache:                 cache,
				ServiceAuthPublicKeys: []string{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkcpsUaeko+BLe9sutR3FRCIQPBwlRU9UN2/69Q4RLb8upVzVcK+22dEJtvVzhu3bl1hgPk3HLIYPrtuLqKOQbw=="},
			}

			resultContext := authenticateService(tc.inputContext, config)
			require.Equal(t, tc.expectedResultContext, resultContext)
		})
	}
}

func TestGenerateServiceAuthenticationPayload_noPrivateKeysProvided(t *testing.T) {
	payload, err := GenerateServiceAuthenticationPayload("users", []string{})
	require.Error(t, err)
	require.Empty(t, payload)
}

func TestGenerateServiceAuthenticationPayload_couldNotParsePEM(t *testing.T) {
	payload, err := GenerateServiceAuthenticationPayload("users", []string{"invalid_PEM"})
	require.Error(t, err)
	require.Empty(t, payload)
}

func TestGenerateServiceAuthenticationPayload_success(t *testing.T) {
	validPEM := "MHcCAQEEINIZr7eRHNKIo+kqyLU5j8Y3mRmfn+5k2OY685DzM1MOoAoGCCqGSM49AwEHoUQDQgAEkcpsUaeko+BLe9sutR3FRCIQPBwlRU9UN2/69Q4RLb8upVzVcK+22dEJtvVzhu3bl1hgPk3HLIYPrtuLqKOQbw=="
	payload, err := GenerateServiceAuthenticationPayload("users", []string{validPEM})
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	expectedPayloadPattern := `^users\.\d+\.[a-zA-Z0-9]{10}\.[a-zA-Z0-9+/=]+$`
	regex := regexp.MustCompile(expectedPayloadPattern)

	require.True(t, regex.MatchString(payload))
}
