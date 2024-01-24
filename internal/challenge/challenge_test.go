package challenge

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kyamalabs/auth/pkg/util"

	"github.com/kyamalabs/auth/internal/cache"

	mockcache "github.com/kyamalabs/auth/internal/cache/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestGenerateChallenge(t *testing.T) {
	wallet, err := util.NewEthereumWallet()
	require.NoError(t, err)

	testCases := []struct {
		name                string
		expectedCacheSetErr error
		expectedToErr       bool
	}{
		{
			name:                "Success",
			expectedCacheSetErr: nil,
			expectedToErr:       false,
		},
		{
			name:                "Failure - could not store challenge in cache",
			expectedCacheSetErr: errors.New("some cache error"),
			expectedToErr:       true,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			c := mockcache.NewMockCache(ctrl)

			var capturedChallenge string
			c.EXPECT().
				Set(gomock.Any(), fmt.Sprintf("%s:%s", cacheKeyPrefix, wallet.Address), gomock.Any(), expiration).
				Times(1).
				Do(func(_ context.Context, _ string, challenge string, _ time.Duration) {
					capturedChallenge = challenge
				}).
				Return(tc.expectedCacheSetErr)

			challenge, err := GenerateChallenge(context.Background(), c, wallet.Address)
			if tc.expectedToErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, challenge)
			require.Equal(t, capturedChallenge, challenge)

			if !strings.HasPrefix(challenge, prefix) {
				require.Fail(t, "challenge had invalid prefix")
			}

			re := regexp.MustCompile(pattern)
			if !re.MatchString(challenge) {
				require.Fail(t, "challenge is formatted incorrectly")
			}
		})
	}
}

func TestFetchChallenge(t *testing.T) {
	wallet, err := util.NewEthereumWallet()
	require.NoError(t, err)

	testCases := []struct {
		name                     string
		expectedCacheGetResult   interface{}
		expectedCacheGetError    error
		shouldCallCacheDelete    bool
		expectedCacheDeleteError error
		expectedChallenge        string
		expectedToErr            bool
	}{
		{
			name:                   "Success",
			expectedCacheGetResult: "Kyama Games: Rottweiler: 6125",
			expectedCacheGetError:  nil,
			shouldCallCacheDelete:  true,
			expectedChallenge:      "Kyama Games: Rottweiler: 6125",
			expectedToErr:          false,
		},
		{
			name:                   "Failure - challenge not present in cache",
			expectedCacheGetResult: nil,
			expectedCacheGetError:  nil,
			expectedChallenge:      "",
			expectedToErr:          true,
		},
		{
			name:                   "Failure - couldn't fetch challenge from cache",
			expectedCacheGetResult: "Kyama Games: Rottweiler: 6125",
			expectedCacheGetError:  errors.New("some cache error"),
			expectedChallenge:      "",
			expectedToErr:          true,
		},
		{
			name:                   "Failure - couldn't cast challenge to string",
			expectedCacheGetResult: 420,
			expectedCacheGetError:  nil,
			expectedChallenge:      "",
			expectedToErr:          true,
		},
		{
			name:                     "Failure - error deleting challenge key from cache",
			expectedCacheGetResult:   "Kyama Games: Rottweiler: 6125",
			expectedCacheGetError:    nil,
			shouldCallCacheDelete:    true,
			expectedCacheDeleteError: errors.New("some cache delete error"),
			expectedChallenge:        "",
			expectedToErr:            true,
		},
		{
			name:                     "Failure - challenge key not present in cache",
			expectedCacheGetResult:   "",
			expectedCacheGetError:    nil,
			shouldCallCacheDelete:    true,
			expectedCacheDeleteError: cache.Nil,
			expectedChallenge:        "",
			expectedToErr:            false,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			c := mockcache.NewMockCache(ctrl)

			c.EXPECT().
				Get(gomock.Any(), fmt.Sprintf("%s:%s", cacheKeyPrefix, wallet.Address)).
				Times(1).
				Return(tc.expectedCacheGetResult, tc.expectedCacheGetError)

			if tc.shouldCallCacheDelete {
				c.EXPECT().
					Del(gomock.Any(), fmt.Sprintf("%s:%s", cacheKeyPrefix, wallet.Address)).
					Times(1).
					Return(tc.expectedCacheDeleteError)
			}

			challenge, err := FetchChallenge(context.Background(), c, wallet.Address)
			if tc.expectedToErr {
				require.Error(t, err)
			}

			require.Equal(t, challenge, tc.expectedChallenge)
		})
	}
}

func TestValidateChallenge(t *testing.T) {
	testCases := []struct {
		name        string
		challenge   string
		expectedErr error
	}{
		{
			name:        "Success",
			challenge:   "Kyama Games: Authentication Challenge: Rottweiler: 6125",
			expectedErr: nil,
		},
		{
			name:        "Failure - missing prefix",
			challenge:   "Rottweiler: 6125",
			expectedErr: InvalidChallengeError,
		},
		{
			name:        "Failure - invalid syntax",
			challenge:   "Kyama Games-Rottweiler-6125",
			expectedErr: InvalidChallengeError,
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			err := ValidateChallenge(tc.challenge)
			require.Equal(t, tc.expectedErr, err)
		})
	}
}

func TestGenerateRandomChallengeSuffix(t *testing.T) {
	challengeSuffix, err := generateRandomChallengeSuffix(4)
	require.NoError(t, err)
	require.NotEmpty(t, challengeSuffix)

	require.Len(t, challengeSuffix, 4)

	challengeSuffixInt, err := strconv.Atoi(challengeSuffix)
	require.NoError(t, err)
	require.NotEmpty(t, challengeSuffixInt)
}
