// Code generated by cmd/cgo -godefs; DO NOT EDIT.
// cgo -godefs -- -I ../../ebpf/c -I ../../../ebpf/c -fsigned-char http_types.go

package http

type httpConnTuple struct {
	Saddr_h  uint64
	Saddr_l  uint64
	Daddr_h  uint64
	Daddr_l  uint64
	Sport    uint16
	Dport    uint16
	Netns    uint32
	Pid      uint32
	Metadata uint32
}
type sslSock struct {
	Tup       httpConnTuple
	Fd        uint32
	Pad_cgo_0 [4]byte
}
type sslReadArgs struct {
	Ctx *byte
	Buf *byte
}

type ebpfHttpTx struct {
	Tup                  httpConnTuple
	Request_started      uint64
	Request_method       uint8
	Response_status_code uint16
	Response_last_seen   uint64
	Request_fragment     [160]byte
	Tcp_seq              uint32
	Tags                 uint64
}
type ebpfHttp2Tx struct {
	Tup                   httpConnTuple
	Response_last_seen    uint64
	Request_started       uint64
	Response_status_code  uint16
	Request_method        uint8
	Path_size             uint8
	Request_end_of_stream bool
	Pad_cgo_0             [3]byte
	Request_path          [30]uint8
	Pad_cgo_1             [2]byte
}

type libPath struct {
	Pid uint32
	Len uint32
	Buf [120]byte
}

type ProtocolType uint8

const (
	ProtocolUnknown  ProtocolType = 0x1
	ProtocolHTTP     ProtocolType = 0x2
	ProtocolHTTP2    ProtocolType = 0x3
	ProtocolTLS      ProtocolType = 0x4
	ProtocolMONGO    ProtocolType = 0x6
	ProtocolPostgres ProtocolType = 0x7
	ProtocolAMQP     ProtocolType = 0x8
	ProtocolRedis    ProtocolType = 0x9
	ProtocolMySQL    ProtocolType = 0xa
	ProtocolMax      ProtocolType = 0xb
)

const (
	HTTPBufferSize  = 0xa0
	HTTP2BufferSize = 0xa0

	libPathMaxSize = 0x78
)

type ConnTag = uint64

const (
	GnuTLS  ConnTag = 0x1
	OpenSSL ConnTag = 0x2
	Go      ConnTag = 0x4
)

var (
	StaticTags = map[ConnTag]string{
		GnuTLS:  "tls.library:gnutls",
		OpenSSL: "tls.library:openssl",
		Go:      "tls.library:go",
	}
)

type StaticTableEnumKey = uint8

const (
	MethodKey StaticTableEnumKey = 0x2
	PathKey   StaticTableEnumKey = 0x4
	StatusKey StaticTableEnumKey = 0x9
)

type StaticTableEnumValue = uint8

const (
	GetValue       StaticTableEnumValue = 0x2
	PostValue      StaticTableEnumValue = 0x3
	EmptyPathValue StaticTableEnumValue = 0x4
	IndexPathValue StaticTableEnumValue = 0x5
	K200Value      StaticTableEnumValue = 0x8
	K204Value      StaticTableEnumValue = 0x9
	K206Value      StaticTableEnumValue = 0xa
	K304Value      StaticTableEnumValue = 0xb
	K400Value      StaticTableEnumValue = 0xc
	K404Value      StaticTableEnumValue = 0xd
	K500Value      StaticTableEnumValue = 0xe
)

type StaticTableValue = struct {
	Key   uint8
	Value uint8
}
