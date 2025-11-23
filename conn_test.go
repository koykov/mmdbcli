package mmdbcli

import (
	"context"
	"testing"
)

func TestConn(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		c, err := Connect("testdata/GeoIP2-City-Test.mmdb")
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.Gets(context.Background(), "81.2.69.142")
		if err != nil {
			t.Fatal(err)
		}
		t.Log(r.Get("country.iso_code")) // todo parse me
	})
}
