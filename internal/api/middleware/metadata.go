package middleware

import (
	"context"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const (
	grpcGatewayUserAgentHeader = "grpcgateway-user-agent"
	userAgentHeader            = "user-agent"
	xForwardedForHeader        = "x-forwarded-for"
)

type Metadata struct {
	UserAgent string `json:"user_agent"`
	ClientIP  string `json:"client_ip"`
}

func ExtractMetadata(ctx context.Context) *Metadata {
	mtdt := &Metadata{}

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		userAgents := md.Get(grpcGatewayUserAgentHeader)
		if len(userAgents) > 0 {
			mtdt.UserAgent = userAgents[0]
		}

		userAgents = md.Get(userAgentHeader)
		if len(userAgents) > 0 {
			mtdt.UserAgent = userAgents[0]
		}

		clientIPs := md.Get(xForwardedForHeader)
		if len(clientIPs) > 0 {
			mtdt.ClientIP = clientIPs[0]
		}
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		mtdt.ClientIP = p.Addr.String()
	}

	return mtdt
}
