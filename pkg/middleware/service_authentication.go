package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kyamagames/auth/internal/api/middleware"
	"github.com/kyamagames/auth/internal/cache"
	"github.com/kyamagames/auth/internal/utils"
	"github.com/rs/zerolog/log"

	"google.golang.org/grpc"
)

const (
	serviceAuthenticationNonceLength     = 10
	serviceAuthenticationPayloadDuration = time.Minute
	serviceAuthenticationCacheKeyPrefix  = "service-auth"
)

type AuthenticateServiceConfig struct {
	Cache                 cache.Cache
	ServiceAuthPublicKeys []string
}

func authenticateService(ctx context.Context, c *AuthenticateServiceConfig) context.Context {
	serviceAuthenticationVal, ok := ctx.Value(middleware.ServiceAuthentication).(string)
	if !ok {
		return ctx
	}

	logger := log.With().Str("payload", serviceAuthenticationVal).Logger()

	splitServiceAuthenticationVal := strings.Split(serviceAuthenticationVal, ".")
	if len(splitServiceAuthenticationVal) != 4 {
		logger.Warn().Msg("invalid service authentication payload")
		return ctx
	}

	var serviceName, nonce, signature string
	serviceName, nonce, signature = splitServiceAuthenticationVal[0], splitServiceAuthenticationVal[2], splitServiceAuthenticationVal[3]

	reqTimestampInt, err := strconv.ParseInt(splitServiceAuthenticationVal[1], 10, 64)
	if err != nil {
		logger.Warn().Msg("invalid service authentication request timestamp")
		return ctx
	}

	reqTimestamp := time.Unix(0, reqTimestampInt*int64(time.Millisecond))

	// verify the service name
	if strings.TrimSpace(serviceName) == "" {
		logger.Warn().Msg("service name must be provided")
		return ctx
	}

	// verify that the request was made within an acceptable duration
	if time.Now().UTC().After(reqTimestamp.Add(serviceAuthenticationPayloadDuration)) {
		logger.Warn().Msg("expired service authentication payload")
		return ctx
	}

	// verify nonce is of the correct length
	if len(nonce) != serviceAuthenticationNonceLength {
		logger.Warn().Msg("invalid service authentication nonce")
		return ctx
	}

	// verify the payload signature
	isSignatureValid := false
	payloadVerificationMsg := fmt.Sprintf("%s.%s.%s", serviceName, splitServiceAuthenticationVal[1], nonce)
	for _, publicKeyStr := range c.ServiceAuthPublicKeys {
		publicKey, err := utils.ParsePublicKeyFromPEM(publicKeyStr)
		if err != nil {
			logger.Warn().Str("pem", publicKeyStr).Msg("could not parse public key from PEM")
			return ctx
		}

		isSignatureValid, err = utils.ECDSAVerify([]byte(payloadVerificationMsg), publicKey, signature)
		if err != nil {
			logger.Warn().Str("pem", publicKeyStr).Msg("could not verify service authentication signature")
			return ctx
		}
	}

	if !isSignatureValid {
		logger.Warn().Msg("invalid service authentication signature")
		return ctx
	}

	cacheKey := fmt.Sprintf("%s:%s", serviceAuthenticationCacheKeyPrefix, signature)
	cachedSignature, err := c.Cache.Get(ctx, cacheKey)
	if cachedSignature != nil || err != nil {
		logger.Warn().
			Err(err).
			Interface("cached_signature", cachedSignature).
			Msg("service authentication signature present in cache")
		return ctx
	}

	err = c.Cache.Set(ctx, cacheKey, signature, serviceAuthenticationPayloadDuration)
	if err != nil {
		logger.Warn().Err(err).Msg("could not cache service authentication signature")
		return ctx
	}

	// add authenticated service name to request context
	ctx = context.WithValue(ctx, middleware.AuthenticatedService, strings.ToLower(strings.TrimSpace(serviceName)))

	return ctx
}

func (config *AuthenticateServiceConfig) AuthenticateServiceGrpc(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	ctx = authenticateService(ctx, config)
	return handler(ctx, req)
}

func AuthenticateServiceHTTP(handler http.Handler, config *AuthenticateServiceConfig) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		ctx := authenticateService(req.Context(), config)
		req = req.WithContext(ctx)
		handler.ServeHTTP(res, req)
	})
}

func GenerateServiceAuthenticationPayload(serviceName string, serviceAuthPrivateKeys []string) (string, error) {
	nonce, err := utils.GenerateRandomAlphanumericString(serviceAuthenticationNonceLength)
	if err != nil {
		log.Error().Err(err).Msg("could not generate service authentication nonce")
		return "", err
	}

	currentUTCTimeMillis := time.Now().UTC().UnixNano() / int64(time.Millisecond)
	currentUTCTimeMillisStr := fmt.Sprintf("%d", currentUTCTimeMillis)

	if len(serviceAuthPrivateKeys) < 1 {
		log.Error().Msg("service authentication private keys not provided")
		return "", errors.New("service authentication private keys not provided")
	}

	privateKey, err := utils.ParsePrivateKeyFromPEM(serviceAuthPrivateKeys[len(serviceAuthPrivateKeys)-1])
	if err != nil {
		log.Error().Err(err).Msg("could not parse private key from PEM")
		return "", err
	}

	payloadSignedMsg := fmt.Sprintf("%s.%s.%s", serviceName, currentUTCTimeMillisStr, nonce)
	signature, err := utils.ECDSASign([]byte(payloadSignedMsg), privateKey)
	if err != nil {
		log.Error().Err(err).Msg("could not sign service authentication payload")
		return "", err
	}

	payload := fmt.Sprintf("%s.%s.%s.%s", serviceName, currentUTCTimeMillisStr, nonce, signature)

	return payload, nil
}
