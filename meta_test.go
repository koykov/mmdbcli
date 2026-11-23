package mmdbcli

import (
	"errors"
	"fmt"
	"testing"
)

func TestMeta(t *testing.T) {
	type meta struct {
		fname  string
		expect Meta
		err    error
	}
	tcs := []meta{
		{fname: "GeoIP2-Anonymous-IP-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Anonymous IP Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Anonymous-IP", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x259, recSize: 0x1c}},
		{fname: "GeoIP2-City-Shield-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 City Shield Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-City-Shield", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x60b, recSize: 0x1c}},
		{fname: "GeoIP2-City-Test-Broken-Double-Format",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 City Test Broken Double Format Database (fake GeoIP2 data, for example purposes only)", "zh": "小型数据库"}, dbType: "GeoIP2-City", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x651357b1, ipVer: 0x6, nodec: 0x5ff, recSize: 0x1c}},
		{fname: "GeoIP2-City-Test-Invalid-Node-Count",
			err: ErrBadDB},
		{fname: "GeoIP2-City-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 City Test Database (fake GeoIP2 data, for example purposes only)", "zh": "小型数据库"}, dbType: "GeoIP2-City", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x60b, recSize: 0x1c}},
		{fname: "GeoIP2-Connection-Type-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Connection Type Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Connection-Type", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x254, recSize: 0x1c}},
		{fname: "GeoIP2-Country-Shield-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Country Shield Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Country-Shield", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x6a8, recSize: 0x1c}},
		{fname: "GeoIP2-Country-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Country Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Country", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x6a8, recSize: 0x1c}},
		{fname: "GeoIP2-DensityIncome-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 DensityIncome Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-DensityIncome", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x183, recSize: 0x1c}},
		{fname: "GeoIP2-Domain-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Domain Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Domain", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x342, recSize: 0x1c}},
		{fname: "GeoIP2-Enterprise-Shield-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Enterprise Shield Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Enterprise-Shield", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x29c, recSize: 0x1c}},
		{fname: "GeoIP2-Enterprise-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Enterprise Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Enterprise", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x29c, recSize: 0x1c}},
		{fname: "GeoIP2-IP-Risk-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 IP Risk Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-IP-Risk", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x1ec, recSize: 0x1c}},
		{fname: "GeoIP2-ISP-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 ISP Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-ISP", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x1a24, recSize: 0x1c}},
		{fname: "GeoIP2-Precision-Enterprise-Shield-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Precision Enterprise Shield Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Precision-Enterprise-Shield", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x4ba, recSize: 0x1c}},
		{fname: "GeoIP2-Precision-Enterprise-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Precision Enterprise Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Precision-Enterprise", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x4ba, recSize: 0x1c}},
		{fname: "GeoIP2-Static-IP-Score-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 Static IP Score Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-Static-IP-Score", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x286, recSize: 0x1c}},
		{fname: "GeoIP2-User-Count-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP2 User Count Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP2-User-Count", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x286, recSize: 0x1c}},
		{fname: "GeoIP-Anonymous-Plus",
			expect: Meta{desc: map[string]string{"en": "GeoIP Anonymous Plus Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP-Anonymous-Plus", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x680282d7, ipVer: 0x6, nodec: 0x26c, recSize: 0x1c}},
		{fname: "GeoIP-Anonymous-Plus-Test",
			expect: Meta{desc: map[string]string{"en": "GeoIP Anonymous Plus Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoIP-Anonymous-Plus", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x26c, recSize: 0x1c}},
		{fname: "GeoLite2-ASN-Test",
			expect: Meta{desc: map[string]string{"en": "GeoLite2 ASN Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoLite2-ASN", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x53d, recSize: 0x1c}},
		{fname: "GeoLite2-City-Test",
			expect: Meta{desc: map[string]string{"en": "GeoLite2 City Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoLite2-City", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x5b9, recSize: 0x1c}},
		{fname: "GeoLite2-Country-Test",
			expect: Meta{desc: map[string]string{"en": "GeoLite2 Country Test Database (fake GeoIP2 data, for example purposes only)"}, dbType: "GeoLite2-Country", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x5e1, recSize: 0x1c}},
		{fname: "MaxMind-DB-no-ipv4-search-tree",
			expect: Meta{desc: map[string]string{"en": "MaxMind DB No IPv4 Search Tree"}, dbType: "MaxMind DB No IPv4 Search Tree", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x40, recSize: 0x18}},
		{fname: "MaxMind-DB-string-value-entries",
			expect: Meta{desc: map[string]string{"en": "MaxMind DB String Value Entries (no maps or arrays as values)"}, dbType: "MaxMind DB String Value Entries", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x4, nodec: 0xa3, recSize: 0x18}},
		{fname: "MaxMind-DB-test-broken-pointers-24",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x651357b0, ipVer: 0x4, nodec: 0xa4, recSize: 0x18}},
		{fname: "MaxMind-DB-test-broken-search-tree-24",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x651357b0, ipVer: 0x4, nodec: 0xa4, recSize: 0x18}},
		{fname: "MaxMind-DB-test-decoder",
			expect: Meta{desc: map[string]string{"en": "MaxMind DB Decoder Test database - contains every MaxMind DB data type"}, dbType: "MaxMind DB Decoder Test", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x1aa, recSize: 0x18}},
		{fname: "MaxMind-DB-test-ipv4-24",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x4, nodec: 0xa3, recSize: 0x18}},
		{fname: "MaxMind-DB-test-ipv4-28",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x4, nodec: 0xa3, recSize: 0x1c}},
		{fname: "MaxMind-DB-test-ipv4-32",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x4, nodec: 0xa3, recSize: 0x20}},
		{fname: "MaxMind-DB-test-ipv6-24",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x19f, recSize: 0x18}},
		{fname: "MaxMind-DB-test-ipv6-28",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x19f, recSize: 0x1c}},
		{fname: "MaxMind-DB-test-ipv6-32",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x19f, recSize: 0x20}},
		{fname: "MaxMind-DB-test-metadata-pointers",
			expect: Meta{desc: map[string]string{"en": "Lots of pointers in metadata", "es": "Lots of pointers in metadata", "zh": "Lots of pointers in metadata"}, dbType: "Lots of pointers in metadata", lang: []string{"en", "es", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x14f, recSize: 0x18}},
		{fname: "MaxMind-DB-test-mixed-24",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x1bc, recSize: 0x18}},
		{fname: "MaxMind-DB-test-mixed-28",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x1bc, recSize: 0x1c}},
		{fname: "MaxMind-DB-test-mixed-32",
			expect: Meta{desc: map[string]string{"en": "Test Database", "zh": "Test Database Chinese"}, dbType: "Test", lang: []string{"en", "zh"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x1bc, recSize: 0x20}},
		{fname: "MaxMind-DB-test-nested",
			expect: Meta{desc: map[string]string{"en": "MaxMind DB Nested Data Structures Test database - contains deeply nested map/array structures"}, dbType: "MaxMind DB Nested Data Structures", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x689b7e8d, ipVer: 0x6, nodec: 0x173, recSize: 0x18}},
		{fname: "MaxMind-DB-test-pointer-decoder",
			expect: Meta{desc: map[string]string{"en": "MaxMind DB Decoder Test database - contains every MaxMind DB data type"}, dbType: "MaxMind DB Decoder Test", lang: []string{"en"}, bfmaj: 0x2, bfmin: 0x0, epoch: 0x651357b0, ipVer: 0x6, nodec: 0xbd, recSize: 0x18}},
	}
	metaeq := func(a, b *Meta) map[string]string {
		diff := make(map[string]string)
		if a.dbType != b.dbType {
			diff["database_type"] = fmt.Sprintf("%s != %s", a.dbType, b.dbType)
		}
		if a.bfmaj != b.bfmaj {
			diff["binary_format_major_version"] = fmt.Sprintf("%d != %d", a.bfmaj, b.bfmaj)
		}
		if a.bfmin != b.bfmin {
			diff["binary_format_minor_version"] = fmt.Sprintf("%d != %d", a.bfmin, b.bfmin)
		}
		if a.epoch != b.epoch {
			diff["build_epoch"] = fmt.Sprintf("%d != %d", a.epoch, b.epoch)
		}
		if a.ipVer != b.ipVer {
			diff["ip_version"] = fmt.Sprintf("%d != %d", a.ipVer, b.ipVer)
		}
		if a.recSize != b.recSize {
			diff["record_size"] = fmt.Sprintf("%d != %d", a.recSize, b.recSize)
		}
		if a.nodec != b.nodec {
			diff["node_count"] = fmt.Sprintf("%d != %d", a.nodec, b.nodec)
		}
		if descA, descB := fmt.Sprintf("%v", a.desc), fmt.Sprintf("%v", b.desc); descA != descB {
			diff["description"] = fmt.Sprintf("%v != %v", descA, descB)
		}
		if langA, langB := fmt.Sprintf("%v", a.lang), fmt.Sprintf("%v", b.lang); langA != langB {
			diff["languages"] = fmt.Sprintf("%v != %v", langA, langB)
		}
		return diff
	}
	for _, tc := range tcs {
		t.Run(tc.fname, func(t *testing.T) {
			fpath := fmt.Sprintf("testdata/%s.mmdb", tc.fname)
			cn, err := Connect(fpath)
			if tc.err != nil {
				if !errors.Is(tc.err, err) {
					t.Error(err)
				}
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = cn.Close() }()
			if diff := metaeq(cn.Meta(), &tc.expect); len(diff) > 0 {
				t.Error(diff)
			}
		})
	}
}

func BenchmarkMeta(b *testing.B) {
	tcs := []string{
		"MaxMind-DB-test-metadata-pointers",
	}
	for _, tc := range tcs {
		b.Run(tc, func(b *testing.B) {
			fpath := fmt.Sprintf("testdata/%s.mmdb", tc)
			c, err := connect(fpath)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.meta.reset()
				_ = c.decodeMeta()
			}
		})
	}
}
