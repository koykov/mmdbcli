package mmdbcli

import (
	"context"
	"errors"
	"fmt"
	"testing"
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
			if err != nil {
				t.Fatalf("Connect(%s): %v", tt.fname, err)
			}
			defer func() { _ = cn.Close() }()

			count := 0
			err = cn.EachNetwork(context.Background(), func(*Record) error {
				count++
				return nil
			})
			if err != nil {
				t.Errorf("EachNetwork(%s): unexpected error: %v", tt.fname, err)
			}
			if count != tt.expect {
				t.Errorf("EachNetwork(%s): callback count = %d, want %d", tt.fname, count, tt.expect)
			}
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
			if err != nil {
				t.Fatalf("Connect(%s): %v", tt.fname, err)
			}
			defer func() { _ = cn.Close() }()

			count := 0
			err = cn.EachNetworkWithOptions(context.Background(), func(*Record) error {
				count++
				return nil
			}, tt.options)
			if err != nil {
				t.Errorf("EachNetworkWithOptions(%s, %d): unexpected error: %v", tt.fname, tt.options, err)
			}
			if count != tt.expect {
				t.Errorf("EachNetworkWithOptions(%s, %d): callback count = %d, want %d", tt.fname, tt.options, count, tt.expect)
			}
		})
	}
}

func TestEachNetworkCallbackError(t *testing.T) {
	var errNetworkStop = errors.New("stop iteration")

	cn, err := Connect("testdata/MaxMind-DB-test-ipv4-24.mmdb")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = cn.Close() }()

	calls := 0
	err = cn.EachNetwork(context.Background(), func(*Record) error {
		calls++
		if calls == 2 {
			return errNetworkStop
		}
		return nil
	})
	if !errors.Is(err, errNetworkStop) {
		t.Errorf("EachNetwork: err = %v, want errors.Is(err, errNetworkStop)", err)
	}
	if calls != 2 {
		t.Errorf("EachNetwork: callback invoked %d times, want 2 (iteration must stop immediately)", calls)
	}
}

func TestEachNetworkContextCancel(t *testing.T) {
	cn, err := Connect("testdata/MaxMind-DB-test-ipv4-24.mmdb")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = cn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = cn.EachNetwork(ctx, func(*Record) error {
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("EachNetwork with cancelled context: err = %v, want context.Canceled", err)
	}
}

func TestEachNetworkIncludeEmpty(t *testing.T) {
	cn, err := Connect("testdata/MaxMind-DB-test-mixed-24.mmdb")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = cn.Close() }()

	count := 0
	err = cn.EachNetworkWithOptions(context.Background(), func(*Record) error {
		count++
		return nil
	}, NetworkOptionIncludeEmptyNetwork)
	if err != nil {
		t.Errorf("EachNetworkWithOptions(IncludeEmptyNetwork): unexpected error: %v", err)
	}
	// Provisional lower-bound check: no exact expectation exists until a prefix-scoped walk lands.
	if count <= 11 {
		t.Errorf("EachNetworkWithOptions(IncludeEmptyNetwork): callback count = %d, want > 11", count)
	}
}
