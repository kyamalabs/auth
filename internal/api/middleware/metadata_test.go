package middleware

import (
	"context"
	"testing"

	"github.com/kyamagames/auth/internal/token"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

func TestExtractMetadata(t *testing.T) {
	testCases := []struct {
		name          string
		buildContext  func(t *testing.T, tokenMaker token.Maker) context.Context
		checkResponse func(t *testing.T, mtdt *Metadata)
	}{
		{
			name: "Success - extracts grpcgateway-user-agent header",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				md := metadata.MD{
					grpcGatewayUserAgentHeader: []string{
						"test_val",
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			checkResponse: func(t *testing.T, mtdt *Metadata) {
				require.NotEmpty(t, mtdt)

				require.Equal(t, "test_val", mtdt.UserAgent)
			},
		},
		{
			name: "Success - extracts user-agent header",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				md := metadata.MD{
					userAgentHeader: []string{
						"test_val",
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			checkResponse: func(t *testing.T, mtdt *Metadata) {
				require.NotEmpty(t, mtdt)

				require.Equal(t, "test_val", mtdt.UserAgent)
			},
		},
		{
			name: "Success - extracts x-forwarded-for header",
			buildContext: func(t *testing.T, tokenMaker token.Maker) context.Context {
				md := metadata.MD{
					xForwardedForHeader: []string{
						"test_val",
					},
				}

				return metadata.NewIncomingContext(context.Background(), md)
			},
			checkResponse: func(t *testing.T, mtdt *Metadata) {
				require.NotEmpty(t, mtdt)

				require.Equal(t, "test_val", mtdt.ClientIP)
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			tokenMaker := getTestTokenMaker(t)
			ctx := tc.buildContext(t, tokenMaker)

			mtdt := ExtractMetadata(ctx)
			tc.checkResponse(t, mtdt)
		})
	}
}
