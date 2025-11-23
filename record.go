package mmdbcli

import (
	"github.com/koykov/indirect"
	"github.com/koykov/simd/indextoken"
)

type Record struct {
	cnptr    uintptr
	off, pfx uint64
}

func (r *Record) Get(path string) *Value {
	cn := r.indirectConn()
	if cn == nil {
		return nil
	}
	var t indextoken.Tokenizer[string]
	return cn.lookup(r.off, path, &t)
}

func (r *Record) indirectConn() *conn {
	if r.cnptr == 0 {
		return nil
	}
	return (*conn)(indirect.ToUnsafePtr(r.cnptr))
}
