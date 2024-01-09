package middleware

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestInitializeLimiters(t *testing.T) {
	testCases := []struct {
		name                string
		rateLimits          map[string]rate
		expectedNumLimiters int
	}{
		{
			name: "only default rate limit",
			rateLimits: map[string]rate{
				defaultRateLimitIdentifier: {Limit: 1000, Period: time.Hour, Identifier: defaultRateLimitIdentifier},
			},
			expectedNumLimiters: 1,
		},
		{
			name: "with additional endpoint rate limits",
			rateLimits: map[string]rate{
				defaultRateLimitIdentifier: {Limit: 1000, Period: time.Hour, Identifier: defaultRateLimitIdentifier},
				"/pb.Auth/GetChallenge":    {Limit: 100, Period: time.Hour, Identifier: "gRPC Challenge"},
				"/auth/accounts/challenge": {Limit: 100, Period: time.Hour, Identifier: "HTTP Challenge"},
			},
			expectedNumLimiters: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.NewStore()

			initialRateLimits := rateLimits
			rateLimits = tc.rateLimits
			defer func() {
				rateLimits = initialRateLimits
			}()

			err := InitializeLimiters(store)
			require.NoError(t, err)
			require.Len(t, limiters, 1)
		})
	}
}

func TestGetEndpointRateLimit(t *testing.T) {
	defaultRateLimit := rate{Limit: 1000, Period: time.Hour, Identifier: defaultRateLimitIdentifier}
	testRateLimit := rate{Limit: 1000, Period: time.Hour, Identifier: "Test"}

	testCases := []struct {
		name              string
		endpoint          string
		rateLimits        map[string]rate
		expectedRateLimit rate
	}{
		{
			name:     "relies on default rate limit",
			endpoint: "/test",
			rateLimits: map[string]rate{
				defaultRateLimitIdentifier: defaultRateLimit,
			},
			expectedRateLimit: defaultRateLimit,
		},
		{
			name:     "has a specific rate limit",
			endpoint: "/test",
			rateLimits: map[string]rate{
				defaultRateLimitIdentifier: defaultRateLimit,
				"/test":                    testRateLimit,
			},
			expectedRateLimit: testRateLimit,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initialRateLimits := rateLimits
			rateLimits = tc.rateLimits
			defer func() {
				rateLimits = initialRateLimits
			}()

			rateLimit := getEndpointRateLimit(tc.endpoint)

			require.Equal(t, tc.expectedRateLimit, rateLimit)
		})
	}
}

func TestGetLimiter(t *testing.T) {
	testRateLimit := rate{Limit: 1000, Period: time.Hour, Identifier: "Test"}
	uninitializedRateLimit := rate{Limit: 1000, Period: time.Hour, Identifier: "Uninitialized"}

	initialRateLimits := rateLimits
	rateLimits = map[string]rate{
		"/test": testRateLimit,
	}
	defer func() {
		rateLimits = initialRateLimits
	}()

	store := memory.NewStore()

	err := InitializeLimiters(store)
	require.NoError(t, err)

	testCases := []struct {
		name          string
		rateLimit     rate
		expectLimiter bool
	}{
		{
			name:          "initialized rate limit",
			rateLimit:     testRateLimit,
			expectLimiter: true,
		},
		{
			name:          "uninitialized rate limit",
			rateLimit:     uninitializedRateLimit,
			expectLimiter: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := getLimiter(tc.rateLimit)
			if !tc.expectLimiter {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, l)
		})
	}
}

type mockUnaryHandler struct {
	resp interface{}
	err  error
}

func (m *mockUnaryHandler) mockHandle(_ context.Context, _ interface{}) (interface{}, error) {
	return m.resp, m.err
}

type mockServerTransportStream struct{}

func (m *mockServerTransportStream) Method() string {
	return "foo"
}

func (m *mockServerTransportStream) SetHeader(_ metadata.MD) error {
	return nil
}

func (m *mockServerTransportStream) SendHeader(_ metadata.MD) error {
	return nil
}

func (m *mockServerTransportStream) SetTrailer(_ metadata.MD) error {
	return nil
}

func TestGrpcRateLimiter(t *testing.T) {
	testCases := []struct {
		name               string
		rateLimits         map[string]rate
		clientIP           string
		limiterContext     limiter.Context
		getLimiterCtxError error
		expectedError      string
	}{
		{
			name:           "valid request",
			rateLimits:     map[string]rate{defaultRateLimitIdentifier: {Limit: 1000, Period: time.Hour, Identifier: defaultRateLimitIdentifier}},
			clientIP:       "127.0.0.1",
			limiterContext: limiter.Context{Limit: 10, Remaining: 9, Reset: time.Now().Add(1 * time.Minute).Unix(), Reached: false},
			expectedError:  "",
		},
		{
			name:           "exceeded rate limit",
			rateLimits:     map[string]rate{defaultRateLimitIdentifier: {Limit: 1000, Period: time.Hour, Identifier: defaultRateLimitIdentifier}},
			clientIP:       "127.0.0.1",
			limiterContext: limiter.Context{Limit: 10, Remaining: 0, Reset: time.Now().Add(1 * time.Minute).Unix(), Reached: true},
			expectedError:  RateLimitExceededError,
		},
		{
			name:           "could not get rate limiter",
			rateLimits:     map[string]rate{},
			clientIP:       "127.0.0.1",
			limiterContext: limiter.Context{Limit: 10, Remaining: 9, Reset: time.Now().Add(1 * time.Minute).Unix(), Reached: false},
			expectedError:  InternalServerError,
		},
		{
			name:           "missing x-forwarded-for header",
			rateLimits:     map[string]rate{defaultRateLimitIdentifier: {Limit: 1000, Period: time.Hour, Identifier: defaultRateLimitIdentifier}},
			clientIP:       "",
			limiterContext: limiter.Context{Limit: 10, Remaining: 9, Reset: time.Now().Add(1 * time.Minute).Unix(), Reached: false},
			expectedError:  MissingXForwardedForHeaderError,
		},
		{
			name:               "could not get limiter context",
			rateLimits:         map[string]rate{defaultRateLimitIdentifier: {Limit: 1000, Period: time.Hour, Identifier: defaultRateLimitIdentifier}},
			clientIP:           "127.0.0.1",
			limiterContext:     limiter.Context{Limit: 10, Remaining: 9, Reset: time.Now().Add(1 * time.Minute).Unix(), Reached: false},
			getLimiterCtxError: errors.New("some error"),
			expectedError:      InternalServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize default rate limiter
			store := memory.NewStore()
			initialRateLimits := rateLimits
			rateLimits = tc.rateLimits
			defer func() {
				rateLimits = initialRateLimits
			}()
			err := InitializeLimiters(store)
			require.NoError(t, err)

			// add x-forwarded header to incoming context
			ctx := grpc.NewContextWithServerTransportStream(context.Background(), &mockServerTransportStream{})
			ctxWithHeader := metadata.NewIncomingContext(ctx, metadata.Pairs(xForwardedForHeader, tc.clientIP))

			initialGetLimiterContext := getLimiterContext
			getLimiterContext = func(ctx context.Context, l *limiter.Limiter, key string) (limiter.Context, error) {
				return tc.limiterContext, tc.getLimiterCtxError
			}
			defer func() {
				getLimiterContext = initialGetLimiterContext
			}()

			mockHandler := &mockUnaryHandler{
				resp: "success",
				err:  nil,
			}

			_, err = GrpcRateLimiter(ctxWithHeader, nil, &grpc.UnaryServerInfo{
				FullMethod: "/test",
			}, mockHandler.mockHandle)

			if tc.expectedError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.ErrorContains(t, err, tc.expectedError)
		})
	}
}
