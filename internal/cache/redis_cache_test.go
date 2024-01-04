package cache

import (
	"context"
	"testing"
	"time"

	"github.com/kyamagames/auth/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestRedisCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test to maintain redis cache state")
	}

	config, err := utils.LoadConfig("../../")
	require.NoError(t, err)
	require.NotEmpty(t, config)

	redisCache, err := NewRedisCache(config.RedisConnURL)
	require.NoError(t, err)
	require.NotEmpty(t, redisCache)

	testCases := []struct {
		name           string
		key            string
		value          interface{}
		shouldSetValue bool
		checkValue     func(t *testing.T, res interface{}, err error, val interface{})
	}{
		{
			name:           "Success - nil",
			key:            "test_key:nil",
			value:          nil,
			shouldSetValue: false,
			checkValue: func(t *testing.T, res interface{}, err error, val interface{}) {
				require.NoError(t, err)
				require.Nil(t, res)
			},
		},
		{
			name:           "Success - string",
			key:            "test_key:string",
			value:          "some_string_value",
			shouldSetValue: true,
			checkValue: func(t *testing.T, res interface{}, err error, val interface{}) {
				require.NoError(t, err)
				require.NotEmpty(t, res)

				cachedVal, ok := res.(string)
				require.True(t, ok)
				require.Equal(t, val, cachedVal)
			},
		},
		{
			name:           "Success - int",
			key:            "test_key:int",
			value:          6379,
			shouldSetValue: true,
			checkValue: func(t *testing.T, res interface{}, err error, val interface{}) {
				require.NoError(t, err)
				require.NotEmpty(t, res)

				cachedVal, ok := res.(float64)
				require.True(t, ok)
				require.Equal(t, val, int(cachedVal))
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]

		t.Run(tc.name, func(t *testing.T) {
			if tc.shouldSetValue {
				err = redisCache.Set(context.Background(), tc.key, tc.value, 30*time.Second)
				require.NoError(t, err)
			}

			res, err := redisCache.Get(context.Background(), tc.key)
			tc.checkValue(t, res, err, tc.value)
		})
	}
}
