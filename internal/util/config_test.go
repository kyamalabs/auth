package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("./testdata")
	require.NoError(t, err)

	require.Equal(t, "test_db_driver", config.DBDriver)
}
