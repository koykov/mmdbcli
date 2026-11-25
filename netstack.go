package mmdbcli

import "sync"

type netstknode struct {
	node  uint64
	addr  [16]byte
	depth uint64
}

type netstk []netstknode

func (s *netstk) push(node netstknode) {
	*s = append(*s, node)
}

func (s *netstk) pop() netstknode {
	top := (*s)[s.len()-1]
	*s = (*s)[:len(*s)-1]
	return top
}

func (s *netstk) len() int {
	return len(*s)
}

func (s *netstk) top() netstknode {
	return (*s)[s.len()-1]
}

func (s *netstk) reset() {
	*s = (*s)[:0]
}

func netstkack() *netstk {
	return stkpool.Get().(*netstk)
}

func netstkrel(x *netstk) {
	x.reset()
	stkpool.Put(x)
}

var stkpool = sync.Pool{New: func() any { stk := make(netstk, 0, 128); return &stk }}
