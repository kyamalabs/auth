package challenge

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/kyamagames/auth/internal/cache"
)

const (
	prefix         = "Kyama Games: Authentication Challenge"
	pattern        = "(.+): (.+): (.+): (\\d{4})"
	suffixLen      = 4
	expiration     = 1 * time.Hour
	cacheKeyPrefix = "auth-challenge"
)

var InvalidChallengeError = errors.New("invalid challenge")

func GenerateChallenge(ctx context.Context, cache cache.Cache, walletAddress string) (string, error) {
	cacheKey := fmt.Sprintf("%s:%s", cacheKeyPrefix, walletAddress)

	randomNum, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return "", fmt.Errorf("could not generate random number: %w", err)
	}

	challengeBody := gofakeit.Dog()
	if randomNum.Int64() == 1 {
		challengeBody = gofakeit.Cat()
	}

	randomChallengeSuffix, err := generateRandomChallengeSuffix(suffixLen)
	if err != nil {
		return "", fmt.Errorf("could not generate random challenge number: %w", err)
	}

	challenge := fmt.Sprintf("%s: %s: %s", prefix, challengeBody, randomChallengeSuffix)

	err = cache.Set(ctx, cacheKey, challenge, expiration)
	if err != nil {
		return "", fmt.Errorf("could not store challenge in cache: %w", err)
	}

	return challenge, nil
}

func FetchChallenge(ctx context.Context, cache cache.Cache, walletAddress string) (string, error) {
	cacheKey := fmt.Sprintf("%s:%s", cacheKeyPrefix, walletAddress)

	res, err := cache.Get(ctx, cacheKey)
	if res == nil {
		return "", fmt.Errorf("challenge not present in cache")
	}
	if err != nil {
		return "", fmt.Errorf("could not fetch challenge from cache: %s", res)
	}

	cachedChallenge, ok := res.(string)
	if !ok {
		return "", errors.New("could not cast challenge to string")
	}

	return cachedChallenge, nil
}

func ValidateChallenge(challenge string) error {
	if !strings.HasPrefix(challenge, prefix) {
		return InvalidChallengeError
	}

	re := regexp.MustCompile(pattern)
	if !re.MatchString(challenge) {
		return InvalidChallengeError
	}

	return nil
}

func generateRandomChallengeSuffix(length int) (string, error) {
	maxNum := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)

	randomNum, err := rand.Int(rand.Reader, maxNum)
	if err != nil {
		return "", fmt.Errorf("could not generate random number: %w", err)
	}

	randomStr := fmt.Sprintf("%0*s", length, randomNum)

	return randomStr, nil
}
