package mmdbcli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConn(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		c, err := Connect("testdata/GeoIP2-City-Test.mmdb")
		require.NoError(t, err, "Connect(GeoIP2-City-Test)")
		r, err := c.Gets(context.Background(), "81.2.69.142")
		require.NoError(t, err, "Gets(81.2.69.142)")
		require.NotNil(t, r, "Gets(81.2.69.142) record")
		t.Log(r.Get("country.iso_code")) // todo parse me
	})
}
