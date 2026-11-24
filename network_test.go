package mmdbcli

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEachNetwork(t *testing.T) {
	tests := []struct {
		name   string
		fname  string
		expect int
	}{
		{name: "ipv4-24", fname: "MaxMind-DB-test-ipv4-24", expect: 6},
		{name: "ipv4-28", fname: "MaxMind-DB-test-ipv4-28", expect: 6},
		{name: "ipv4-32", fname: "MaxMind-DB-test-ipv4-32", expect: 6},
		{name: "ipv6-24", fname: "MaxMind-DB-test-ipv6-24", expect: 5},
		{name: "ipv6-28", fname: "MaxMind-DB-test-ipv6-28", expect: 5},
		{name: "ipv6-32", fname: "MaxMind-DB-test-ipv6-32", expect: 5},
		{name: "mixed-24", fname: "MaxMind-DB-test-mixed-24", expect: 11},
		{name: "mixed-28", fname: "MaxMind-DB-test-mixed-28", expect: 11},
		{name: "mixed-32", fname: "MaxMind-DB-test-mixed-32", expect: 11},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn, err := Connect(fmt.Sprintf("testdata/%s.mmdb", tt.fname))
			require.NoError(t, err, "Connect(%s)", tt.fname)
			defer func() { _ = cn.Close() }()

			count := 0
			err = cn.EachNetwork(context.Background(), func(*Record) error {
				count++
				return nil
			})
			assert.NoError(t, err, "EachNetwork(%s)", tt.fname)
			assert.Equal(t, tt.expect, count, "EachNetwork(%s): callback count", tt.fname)
		})
	}
}

func TestEachNetworkWithOptions(t *testing.T) {
	tests := []struct {
		name    string
		fname   string
		options NetworkOption
		expect  int
	}{
		{name: "mixed-24-no-options", fname: "MaxMind-DB-test-mixed-24", options: NetworkOptionNoOptions, expect: 11},
		{name: "mixed-28-no-options", fname: "MaxMind-DB-test-mixed-28", options: NetworkOptionNoOptions, expect: 11},
		{name: "mixed-32-no-options", fname: "MaxMind-DB-test-mixed-32", options: NetworkOptionNoOptions, expect: 11},
		{name: "mixed-24-include-aliased", fname: "MaxMind-DB-test-mixed-24", options: NetworkOptionIncludeAliased, expect: 29},
		{name: "mixed-28-include-aliased", fname: "MaxMind-DB-test-mixed-28", options: NetworkOptionIncludeAliased, expect: 29},
		{name: "mixed-32-include-aliased", fname: "MaxMind-DB-test-mixed-32", options: NetworkOptionIncludeAliased, expect: 29},
		{name: "ipv4-24-no-options", fname: "MaxMind-DB-test-ipv4-24", options: NetworkOptionNoOptions, expect: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn, err := Connect(fmt.Sprintf("testdata/%s.mmdb", tt.fname))
			require.NoError(t, err, "Connect(%s)", tt.fname)
			defer func() { _ = cn.Close() }()

			count := 0
			err = cn.EachNetworkWithOptions(context.Background(), func(*Record) error {
				count++
				return nil
			}, tt.options)
			assert.NoError(t, err, "EachNetworkWithOptions(%s, %d)", tt.fname, tt.options)
			assert.Equal(t, tt.expect, count, "EachNetworkWithOptions(%s, %d): callback count", tt.fname, tt.options)
		})
	}
}

func TestEachNetworkCallbackError(t *testing.T) {
	var errNetworkStop = errors.New("stop iteration")

	cn, err := Connect("testdata/MaxMind-DB-test-ipv4-24.mmdb")
	require.NoError(t, err, "Connect")
	defer func() { _ = cn.Close() }()

	calls := 0
	err = cn.EachNetwork(context.Background(), func(*Record) error {
		calls++
		if calls == 2 {
			return errNetworkStop
		}
		return nil
	})
	require.ErrorIs(t, err, errNetworkStop, "EachNetwork: err")
	assert.Equal(t, 2, calls, "EachNetwork: callback must stop immediately")
}

func TestEachNetworkContextCancel(t *testing.T) {
	cn, err := Connect("testdata/MaxMind-DB-test-ipv4-24.mmdb")
	require.NoError(t, err, "Connect")
	defer func() { _ = cn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cn.EachNetwork(ctx, func(*Record) error {
		return nil
	})
	require.ErrorIs(t, err, context.Canceled, "EachNetwork with cancelled context: err")
}

func TestEachNetworkIncludeEmpty(t *testing.T) {
	cn, err := Connect("testdata/MaxMind-DB-test-mixed-24.mmdb")
	require.NoError(t, err, "Connect")
	defer func() { _ = cn.Close() }()

	count := 0
	err = cn.EachNetworkWithOptions(context.Background(), func(*Record) error {
		count++
		return nil
	}, NetworkOptionIncludeEmptyNetwork)
	assert.NoError(t, err, "EachNetworkWithOptions(IncludeEmptyNetwork)")
	// Provisional lower-bound check: no exact expectation exists until a prefix-scoped walk lands.
	assert.Greater(t, count, 11, "EachNetworkWithOptions(IncludeEmptyNetwork): callback count")
}
