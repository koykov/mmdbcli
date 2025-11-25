package mmdbcli

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"runtime"
	"unsafe"

	"github.com/koykov/byteconv"
	"github.com/koykov/simd/indextoken"
)

const metaPrefix = "\xAB\xCD\xEFMaxMind.com"

type Connection interface {
	Meta() *Meta
	Get(ctx context.Context, ip netip.Addr) (*Record, error)
	Gets(ctx context.Context, ip string) (*Record, error)
	PGet(ctx context.Context, dst *Record, ip netip.Addr) error
	PGets(ctx context.Context, dst *Record, ip string) error
	EachNetwork(ctx context.Context, fn func(*Record) error) error
	EachNetworkWithOptions(ctx context.Context, fn func(*Record) error, options NetworkOption) error
	KeepPtr()
	io.Closer
}

func Connect(filePath string) (c Connection, err error) {
	return connect(filePath)
}

func connect(filePath string) (c *conn, err error) {
	var f *os.File
	if f, err = os.Open(filePath); err != nil {
		return
	}
	fi, err := f.Stat()
	if err != nil {
		return
	}
	cn := &conn{buf: make([]byte, fi.Size())}
	cn.selfptr = uintptr(unsafe.Pointer(cn))
	if _, err = io.ReadFull(f, cn.buf); err != nil {
		return
	}
	i := bytes.LastIndex(cn.buf, []byte(metaPrefix))
	if i == -1 {
		err = ErrMetaNotFound
		return
	}
	cn.bufm = cn.buf[i+len(metaPrefix):]
	if err = cn.decodeMeta(); err != nil {
		return
	}

	cn.nodeoff = cn.meta.recSize / 4
	switch cn.meta.ipVer {
	case 4:
		cn.ipv4bits = 96
	case 6:
		var i, node uint64
		for i = 0; i < 96 && node < cn.meta.nodec; i++ {
			node, err = cn.getNode(node*cn.nodeoff, 0)
			if err != nil {
				return nil, err
			}
		}
		cn.ipv4off, cn.ipv4bits = node, i
	default:
		return nil, ErrMetaIpVersion
	}

	switch cn.meta.recSize {
	case 24:
		cn.trvrsNextFn = traverse24
	case 28:
		cn.trvrsNextFn = traverse28
	case 32:
		cn.trvrsNextFn = traverse32
	default:
		return nil, ErrBadRecordSize
	}

	treesz := cn.meta.nodec * cn.nodeoff
	lo := treesz + 16
	hi := uint64(i - len(metaPrefix))
	if lo > hi {
		return nil, ErrBadDB
	}
	cn.bufr = cn.buf[lo:hi]

	c = cn
	return
}

type conn struct {
	buf      []byte
	bufr     []byte
	bufm     []byte
	meta     Meta
	nodeoff  uint64
	ipv4off  uint64
	ipv4bits uint64
	selfptr  uintptr

	trvrsNextFn func(c *conn, node, bit uint64) (uint64, error)
}

func (c *conn) Meta() *Meta {
	return &c.meta
}

func (c *conn) Get(ctx context.Context, ip netip.Addr) (*Record, error) {
	var t Record
	if err := c.PGet(ctx, &t, ip); err != nil {
		return nil, err
	}
	return &t, nil
}

func (c *conn) Gets(ctx context.Context, ip string) (*Record, error) {
	ip_, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, err
	}
	return c.Get(ctx, ip_)
}

func (c *conn) PGet(ctx context.Context, dst *Record, ip netip.Addr) error {
	if c.meta.ipVer == 4 && ip.Is6() {
		return ErrOverflowPrefix
	}
	node, pfx, err := c.traverse(ctx, &ip, 0, 128)
	if err != nil {
		return err
	}
	if node == c.meta.nodec {
		return nil // empty node
	}
	if node < c.meta.nodec {
		return ErrBadNode
	}

	minNode := c.meta.nodec + 16
	if node < minNode {
		return ErrBadDB
	}
	node -= minNode
	if node >= uint64(len(c.buf)) {
		return ErrBadDB
	}

	dst.cnptr = c.selfptr
	dst.off = node
	dst.pfx = pfx

	return nil
}

func (c *conn) PGets(ctx context.Context, dst *Record, ip string) error {
	ip_, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	return c.PGet(ctx, dst, ip_)
}

func (c *conn) lookup(off uint64, path string, t *indextoken.Tokenizer[string]) *Value {
	_, _ = off, path
	ctrlb := c.bufr[off]
	off++
	etype := entryType(ctrlb >> 5)
	if etype == entryExtended {
		if off > uint64(len(c.bufr)) {
			return nullValue
		}
		etype = entryType(c.bufr[off] + 7)
		off++
	}
	size := ctrlb & 0x1f
	if size == 0 {
		return nil
	}
	switch etype {
	case entryString:
		tkn := t.Next(path)
		if len(tkn) == 0 {
			return &Value{typ: ValueString, cnptr: c.selfptr, off: off}
		}
		return nullValue
	case entryMap:
		tkn := t.Next(path)
		size1 := uint64(ctrlb & 0x1f)
		key := byteconv.B2S(c.bufr[off : off+size1])
		if key != tkn {
			return nullValue
		}
		off += size1
	default:
		return nullValue
	}
	return nullValue
}

func (c *conn) Validate() error {
	// todo implement me
	return nil
}

func (c *conn) Close() error {
	c.meta.reset()
	return nil
}

func (c *conn) KeepPtr() {
	runtime.KeepAlive(c)
}

func (c *conn) getNode(off, bit uint64) (uint64, error) {
	switch c.meta.recSize {
	case 24:
		off += bit * 3
		return (uint64(c.buf[off]) << 16) | (uint64(c.buf[off+1]) << 8) | uint64(c.buf[off+2]), nil
	case 28:
		if bit == 0 {
			return ((uint64(c.buf[off+3]) & 0xF0) << 20) | (uint64(c.buf[off]) << 16) | (uint64(c.buf[off+1]) << 8) | uint64(c.buf[off+2]), nil
		}
		return ((uint64(c.buf[off+3]) & 0x0F) << 24) | (uint64(c.buf[off+4]) << 16) | (uint64(c.buf[off+5]) << 8) | uint64(c.buf[off+6]), nil
	case 32:
		off += bit * 4
		return (uint64(c.buf[off]) << 24) | (uint64(c.buf[off+1]) << 16) | (uint64(c.buf[off+2]) << 8) | uint64(c.buf[off+3]), nil
	default:
		return 0, ErrBadRecordSize
	}
}

func (c *conn) ptr() uintptr {
	return c.selfptr
}
