package mmdbcli

import "context"

type NetworkOption uint64

const (
	NetworkOptionIncludeAliased NetworkOption = 1 << iota
	NetworkOptionIncludeEmptyNetwork
	NetworkOptionSkipEmptyTuple // no-op until value decoding lands
)

const (
	NetworkOptionNoOptions NetworkOption = 0
	NetworkOptionAll                     = NetworkOptionIncludeAliased | NetworkOptionIncludeEmptyNetwork | NetworkOptionSkipEmptyTuple
)

// EachNetwork calls fn for every network; the argument is valid only for the duration of the callback, copy it to retain.
func (c *conn) EachNetwork(ctx context.Context, fn func(*Record) error) error {
	return c.EachNetworkWithOptions(ctx, fn, NetworkOptionNoOptions)
}

// EachNetworkWithOptions calls fn for every selected network; the argument is valid only for the duration of the callback, copy it to retain.
func (c *conn) EachNetworkWithOptions(ctx context.Context, fn func(*Record) error, options NetworkOption) error {
	var startBit uint64
	if c.meta.ipVer == 4 {
		startBit = 96 // IPv4 tree is rooted at ::/96
	}
	return c.netwalk(ctx, fn, 0, startBit, options)
}

func (c *conn) netwalk(ctx context.Context, fn func(*Record) error, root, depth uint64, options NetworkOption) error {
	const maxBits = 128
	stack := netstkack()
	defer netstkrel(stack)
	cur := netstknode{node: root, depth: depth}
	var rec Record
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Aliased subtrees point back to the IPv4 tree; keep only the copy reached through ::/96.
		skip := options&NetworkOptionIncludeAliased == 0 &&
			c.meta.ipVer == 6 && c.ipv4off != 0 && c.ipv4off < c.meta.nodec &&
			cur.node == c.ipv4off && !inIPv4(cur.addr)
		switch {
		case !skip && cur.node < c.meta.nodec:
			if cur.depth >= maxBits {
				return ErrBadDB
			}
			off := cur.node * c.nodeoff
			left, err := c.getNode(off, 0)
			if err != nil {
				return err
			}
			right, err := c.getNode(off, 1)
			if err != nil {
				return err
			}
			raddr := cur.addr
			raddr[cur.depth>>3] |= 1 << (7 - cur.depth&7)
			stack.push(netstknode{node: right, addr: raddr, depth: cur.depth + 1})
			cur.node, cur.depth = left, cur.depth+1
			continue
		case !skip && cur.node > c.meta.nodec:
			off := cur.node - (c.meta.nodec + 16)
			if off >= uint64(len(c.bufr)) {
				return ErrBadDB
			}
			rec = Record{cnptr: c.ptr(), off: off, pfx: cur.depth, addr: cur.addr}
			if err := fn(&rec); err != nil {
				return err
			}
		case !skip && cur.node == c.meta.nodec && options&NetworkOptionIncludeEmptyNetwork != 0:
			rec = Record{cnptr: c.ptr(), off: offNotFound, pfx: cur.depth, addr: cur.addr}
			if err := fn(&rec); err != nil {
				return err
			}
		}
		if stack.len() == 0 {
			return nil
		}
		cur = stack.pop()
	}
}

func inIPv4(a [16]byte) bool {
	for _, b := range a[:12] {
		if b != 0 {
			return false
		}
	}
	return true
}

var _ = NetworkOptionAll
