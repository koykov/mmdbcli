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
		expect []string
	}{
		{
			name:  "ipv4-24",
			fname: "MaxMind-DB-test-ipv4-24",
			expect: []string{
				"1.1.1.1/32",
				"1.1.1.2/31",
				"1.1.1.4/30",
				"1.1.1.8/29",
				"1.1.1.16/28",
				"1.1.1.32/32",
			},
		},
		{
			name:  "ipv4-28",
			fname: "MaxMind-DB-test-ipv4-28",
			expect: []string{
				"1.1.1.1/32",
				"1.1.1.2/31",
				"1.1.1.4/30",
				"1.1.1.8/29",
				"1.1.1.16/28",
				"1.1.1.32/32",
			},
		},
		{
			name:  "ipv4-32",
			fname: "MaxMind-DB-test-ipv4-32",
			expect: []string{
				"1.1.1.1/32",
				"1.1.1.2/31",
				"1.1.1.4/30",
				"1.1.1.8/29",
				"1.1.1.16/28",
				"1.1.1.32/32",
			},
		},
		{
			name:  "ipv6-24",
			fname: "MaxMind-DB-test-ipv6-24",
			expect: []string{
				"::1:ffff:ffff/128",
				"::2:0:0/122",
				"::2:0:40/124",
				"::2:0:50/125",
				"::2:0:58/127",
			},
		},
		{
			name:  "ipv6-28",
			fname: "MaxMind-DB-test-ipv6-28",
			expect: []string{
				"::1:ffff:ffff/128",
				"::2:0:0/122",
				"::2:0:40/124",
				"::2:0:50/125",
				"::2:0:58/127",
			},
		},
		{
			name:  "ipv6-32",
			fname: "MaxMind-DB-test-ipv6-32",
			expect: []string{
				"::1:ffff:ffff/128",
				"::2:0:0/122",
				"::2:0:40/124",
				"::2:0:50/125",
				"::2:0:58/127",
			},
		},
		{
			name:  "mixed-24",
			fname: "MaxMind-DB-test-mixed-24",
			expect: []string{
				"1.1.1.1/32",
				"1.1.1.2/31",
				"1.1.1.4/30",
				"1.1.1.8/29",
				"1.1.1.16/28",
				"1.1.1.32/32",
				"::1:ffff:ffff/128",
				"::2:0:0/122",
				"::2:0:40/124",
				"::2:0:50/125",
				"::2:0:58/127",
			},
		},
		{
			name:  "mixed-28",
			fname: "MaxMind-DB-test-mixed-28",
			expect: []string{
				"1.1.1.1/32",
				"1.1.1.2/31",
				"1.1.1.4/30",
				"1.1.1.8/29",
				"1.1.1.16/28",
				"1.1.1.32/32",
				"::1:ffff:ffff/128",
				"::2:0:0/122",
				"::2:0:40/124",
				"::2:0:50/125",
				"::2:0:58/127",
			},
		},
		{
			name:  "mixed-32",
			fname: "MaxMind-DB-test-mixed-32",
			expect: []string{
				"1.1.1.1/32",
				"1.1.1.2/31",
				"1.1.1.4/30",
				"1.1.1.8/29",
				"1.1.1.16/28",
				"1.1.1.32/32",
				"::1:ffff:ffff/128",
				"::2:0:0/122",
				"::2:0:40/124",
				"::2:0:50/125",
				"::2:0:58/127",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn, err := Connect(fmt.Sprintf("testdata/%s.mmdb", tt.fname))
			require.NoError(t, err, "Connect(%s)", tt.fname)
			defer func() { _ = cn.Close() }()

			var got []string
			err = cn.EachNetwork(context.Background(), func(rec *Record) error {
				got = append(got, rec.Prefix().String())
				return nil
			})
			assert.NoError(t, err, "EachNetwork(%s)", tt.fname)
			assert.Equal(t, tt.expect, got, "%s: network list", tt.fname)
		})
	}
}

func TestEachNetworkWithOptions(t *testing.T) {
	mixedNoOptions := []string{
		"1.1.1.1/32",
		"1.1.1.2/31",
		"1.1.1.4/30",
		"1.1.1.8/29",
		"1.1.1.16/28",
		"1.1.1.32/32",
		"::1:ffff:ffff/128",
		"::2:0:0/122",
		"::2:0:40/124",
		"::2:0:50/125",
		"::2:0:58/127",
	}
	mixedIncludeAliased := []string{
		"1.1.1.1/32",
		"1.1.1.2/31",
		"1.1.1.4/30",
		"1.1.1.8/29",
		"1.1.1.16/28",
		"1.1.1.32/32",
		"::1:ffff:ffff/128",
		"::2:0:0/122",
		"::2:0:40/124",
		"::2:0:50/125",
		"::2:0:58/127",
		"::ffff:1.1.1.1/128",
		"::ffff:1.1.1.2/127",
		"::ffff:1.1.1.4/126",
		"::ffff:1.1.1.8/125",
		"::ffff:1.1.1.16/124",
		"::ffff:1.1.1.32/128",
		"2001:0:101:101::/64",
		"2001:0:101:102::/63",
		"2001:0:101:104::/62",
		"2001:0:101:108::/61",
		"2001:0:101:110::/60",
		"2001:0:101:120::/64",
		"2002:101:101::/48",
		"2002:101:102::/47",
		"2002:101:104::/46",
		"2002:101:108::/45",
		"2002:101:110::/44",
		"2002:101:120::/48",
	}
	ipv4NoOptions := []string{
		"1.1.1.1/32",
		"1.1.1.2/31",
		"1.1.1.4/30",
		"1.1.1.8/29",
		"1.1.1.16/28",
		"1.1.1.32/32",
	}

	tests := []struct {
		name    string
		fname   string
		options NetworkOption
		expect  []string
	}{
		{name: "mixed-24-no-options", fname: "MaxMind-DB-test-mixed-24", options: NetworkOptionNoOptions, expect: mixedNoOptions},
		{name: "mixed-28-no-options", fname: "MaxMind-DB-test-mixed-28", options: NetworkOptionNoOptions, expect: mixedNoOptions},
		{name: "mixed-32-no-options", fname: "MaxMind-DB-test-mixed-32", options: NetworkOptionNoOptions, expect: mixedNoOptions},
		{name: "mixed-24-include-aliased", fname: "MaxMind-DB-test-mixed-24", options: NetworkOptionIncludeAliased, expect: mixedIncludeAliased},
		{name: "mixed-28-include-aliased", fname: "MaxMind-DB-test-mixed-28", options: NetworkOptionIncludeAliased, expect: mixedIncludeAliased},
		{name: "mixed-32-include-aliased", fname: "MaxMind-DB-test-mixed-32", options: NetworkOptionIncludeAliased, expect: mixedIncludeAliased},
		{name: "ipv4-24-no-options", fname: "MaxMind-DB-test-ipv4-24", options: NetworkOptionNoOptions, expect: ipv4NoOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn, err := Connect(fmt.Sprintf("testdata/%s.mmdb", tt.fname))
			require.NoError(t, err, "Connect(%s)", tt.fname)
			defer func() { _ = cn.Close() }()

			var got []string
			err = cn.EachNetworkWithOptions(context.Background(), func(rec *Record) error {
				got = append(got, rec.Prefix().String())
				return nil
			}, tt.options)
			assert.NoError(t, err, "EachNetworkWithOptions(%s, %d)", tt.fname, tt.options)
			assert.Equal(t, tt.expect, got, "%s: network list", tt.fname)
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

func TestEachNetworkIncludeEmptyV6(t *testing.T) {
	cn, err := Connect("testdata/MaxMind-DB-test-ipv6-24.mmdb")
	require.NoError(t, err, "Connect")
	defer func() { _ = cn.Close() }()

	count := 0
	err = cn.EachNetworkWithOptions(context.Background(), func(*Record) error {
		count++
		return nil
	}, NetworkOptionIncludeEmptyNetwork)
	assert.NoError(t, err, "EachNetworkWithOptions(IncludeEmptyNetwork)")
	t.Logf("emitted networks: %d", count)
	// ipv6-24 holds 5 data networks; including empty ones must yield strictly more.
	assert.Greater(t, count, 5, "EachNetworkWithOptions(IncludeEmptyNetwork): callback count")
}

func TestPrefix(t *testing.T) {
	type tst struct {
		name   string
		fname  string
		ip     string
		expect string
	}
	tcs := []tst{
		// Masking is what separates a lookup result from the queried address:
		// each non-canonical IP must report the network it belongs to.
		{name: "ipv4-24/1.1.1.1-exact-host", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.1", expect: "1.1.1.1/32"},
		{name: "ipv4-24/1.1.1.2-two-addr-net-lower", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.2", expect: "1.1.1.2/31"},
		{name: "ipv4-24/1.1.1.3-two-addr-net-upper", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.3", expect: "1.1.1.2/31"},
		{name: "ipv4-24/1.1.1.4-four-addr-net-lower", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.4", expect: "1.1.1.4/30"},
		{name: "ipv4-24/1.1.1.5-four-addr-net-upper", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.5", expect: "1.1.1.4/30"},
		{name: "ipv4-24/1.1.1.8-eight-addr-net", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.8", expect: "1.1.1.8/29"},
		{name: "ipv4-24/1.1.1.16-sixteen-addr-net", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.16", expect: "1.1.1.16/28"},
		{name: "ipv4-24/1.1.1.32-single-addr-net", fname: "MaxMind-DB-test-ipv4-24", ip: "1.1.1.32", expect: "1.1.1.32/32"},

		{name: "ipv6-24/::1:ffff:ffff-exact-host", fname: "MaxMind-DB-test-ipv6-24", ip: "::1:ffff:ffff", expect: "::1:ffff:ffff/128"},
		{name: "ipv6-24/::2:0:1-inside-122-net", fname: "MaxMind-DB-test-ipv6-24", ip: "::2:0:1", expect: "::2:0:0/122"},

		{name: "decoder/1.1.1.3-inside-24-net", fname: "MaxMind-DB-test-decoder", ip: "1.1.1.3", expect: "1.1.1.0/24"},
		// The fixture is an IPv6 database, so an IPv4-mapped address must be
		// looked up as IPv6 rather than rejected with ErrOverflowPrefix.
		{name: "decoder/::ffff:1.1.1.128-ipv4-mapped-inside-120-net", fname: "MaxMind-DB-test-decoder", ip: "::ffff:1.1.1.128", expect: "::ffff:1.1.1.0/120"},

		// No data under 1.1.1.1 here, but the enclosing /8 is still reported.
		{name: "ipv6-32/1.1.1.1-not-found-enclosing-net", fname: "MaxMind-DB-test-ipv6-32", ip: "1.1.1.1", expect: "1.0.0.0/8"},
	}
	for _, tt := range tcs {
		t.Run(tt.name, func(t *testing.T) {
			cn, err := Connect(fmt.Sprintf("testdata/%s.mmdb", tt.fname))
			require.NoError(t, err, "Connect(%s)", tt.fname)
			defer func() { _ = cn.Close() }()

			rec, err := cn.Gets(context.Background(), tt.ip)
			require.NoError(t, err, "Gets(%s, %s)", tt.fname, tt.ip)
			assert.Equal(t, tt.expect, rec.Prefix().String(), "%s: Prefix(%s)", tt.fname, tt.ip)
		})
	}
}
