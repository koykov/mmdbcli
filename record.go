package mmdbcli

import (
	"net/netip"

	"github.com/koykov/indirect"
	"github.com/koykov/simd/indextoken"
)

const offNotFound = ^uint64(0)

type Record struct {
	cnptr uintptr
	off   uint64
	pfx   uint64
	addr  [16]byte
}

func (r *Record) Get(path string) *Value {
	if r.off == offNotFound {
		return nullValue
	}
	cn := r.indirectConn()
	if cn == nil {
		return nil
	}
	var t indextoken.Tokenizer[string]
	return cn.lookup(r.off, path, &t)
}

func (r *Record) Prefix() netip.Prefix {
	if r.pfx == 0 {
		return netip.Prefix{}
	}
	// IPv4 networks are stored under ::/96.
	if r.pfx >= 96 && inIPv4(r.addr) {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{r.addr[12], r.addr[13], r.addr[14], r.addr[15]}), int(r.pfx-96)).Masked()
	}
	return netip.PrefixFrom(netip.AddrFrom16(r.addr), int(r.pfx)).Masked()
}

func (r *Record) indirectConn() *conn {
	if r.cnptr == 0 {
		return nil
	}
	return (*conn)(indirect.ToUnsafePtr(r.cnptr))
}
