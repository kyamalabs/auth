package middleware

// Headers
const (
	AuthorizationHeader        = "authorization"
	AuthorizationBearer        = "bearer"
	userAgentHeader            = "user-agent"
	contentTypeHeader          = "Content-Type"
	applicationJSONValue       = "application/json"
	xForwardedForHeader        = "x-forwarded-for"
	grpcGatewayUserAgentHeader = "grpcgateway-user-agent"
)

// Errors
const (
	InternalServerError             string = "An unexpected error occurred while processing your request."
	RateLimitExceededError          string = "Slow down! Too many requests. Try again shortly. Thank you!"
	MissingXForwardedForHeaderError string = "X-Forwarded-For header is required for accurate processing."
)

type RedisKey string

const (
	clientIP RedisKey = "client_ip"
)
