package mmdbcli

type ValueType uint64

const (
	ValueNull ValueType = iota
	ValueStruct
	ValueMap
	ValueString
	ValueUint
	ValueFloat
	ValueBool
)

type Value struct {
	typ   ValueType
	cnptr uintptr
	off   uint64
}

var nullValue = &Value{}
