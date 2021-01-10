package mrt

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"
)

type BGPAttributFlag uint8
type BGPAttributeType uint8

const (
	PEER_INDEX_TABLE DataSubType = iota + 1
	RIB_IPV4_UNICAST
	RIB_IPV4_MULTICAST
	RIB_IPV6_UNICAST
	RIB_IPV6_MULTICAST
	RIB_GENERIC
)

const (
	BGP_ATTR_TYPE_ORIGIN BGPAttributeType = iota + 1
	BGP_ATTR_TYPE_AS_PATH
	BGP_ATTR_TYPE_NEXT_HOP
	BGP_ATTR_TYPE_MULTI_EXIT_DISC
	BGP_ATTR_TYPE_LOCAL_PREF
	BGP_ATTR_TYPE_ATOMIC_AGGREGATE
	BGP_ATTR_TYPE_AGGREGATOR
	BGP_ATTR_TYPE_COMMUNITY
	BGP_ATTR_TYPE_ORIGINATOR_ID
	BGP_ATTR_TYPE_CLUSTER_LIST
	_
	_
	_
	BGP_ATTR_TYPE_MP_REACH_NLRI
	BGP_ATTR_TYPE_MP_UNREACH_NLRI
	BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
	BGP_ATTR_TYPE_AS4_PATH
	BGP_ATTR_TYPE_AS4_AGGREGATOR
	_
	_
	_
	BGP_ATTR_TYPE_PMSI_TUNNEL
	BGP_ATTR_TYPE_TUNNEL_ENCAPSULAITION
	BGP_ATTR_TYPE_TRAFFIC_ENGINEERING
	BGP_ATTR_TYPE_IPV6_EXTENDED_COMMUNITIES
	BGP_ATTR_TYPE_AIGP
	BGP_ATTR_TYPE_PE_DISTINGUISHER_LABELS
	_
	BGP_ATTR_TYPE_BGP_LS
	_
	_
	BGP_ATTR_TYPE_LARGE_COMMUNITY
	BGP_ATTR_TYPE_BGPSEC_PATH
	_
	_
	_
	BGP_ATTR_TYPE_SFP
	_
	_
	BGP_ATTR_TYPE_PREFIX_SID
)

const (
	BGP_ATTR_FLAG_OPTIONAL   BGPAttributFlag = 0b10000000
	BGP_ATTR_FLAG_TRANSITIVE BGPAttributFlag = 0b01000000
	BGP_ATTR_FLAG_PARTIAL    BGPAttributFlag = 0b00100000
	BGP_ATTR_FLAG_EXTENDED   BGPAttributFlag = 0b00010000
)

type TableDump interface{}

type PeerIndexTable struct {
	CollectorBGPId net.IP
	ViewName       string
	PeerEntries    []PeerEntry
}

type PeerEntry struct {
	PeerIndex     int
	PeerType      uint8
	PeerBGPId     net.IP
	PeerIPAddress net.IP
	PeerAS        uint
}

type RIBTable struct {
	SequenceNum uint32
	PrefixLen   uint8
	Prefix      net.IP
	RIBEntries  []RIBEntry
}

type RIBEntry struct {
	PeerIndex         int
	OriginatedTime    time.Time
	BGPPathAttributes []BGPAttribute
}

type BGPAttribute struct {
	Optional   bool
	Transitive bool
	Partial    bool
	Extended   bool
	Type       BGPAttributeType
	Data       interface{}
}

func ParseTableDumpV2(r io.Reader, subType DataSubType) TableDump {
	switch subType {
	case PEER_INDEX_TABLE:
		return TableDump(ParsePeerIndexTable(r))
	case RIB_IPV6_UNICAST, RIB_IPV6_MULTICAST:
		return TableDump(ParseRIBIPV6(r))
	}
	return nil
}

func ParsePeerIndexTable(r io.Reader) PeerIndexTable {
	table := PeerIndexTable{}
	var header struct {
		CollectorBGPId [4]byte
		ViewNameLength uint16
	}

	binary.Read(r, binary.BigEndian, &header)

	table.CollectorBGPId = header.CollectorBGPId[:]

	if header.ViewNameLength > 0 {
		viewName := make([]byte, header.ViewNameLength)
		binary.Read(r, binary.BigEndian, &viewName)
		table.ViewName = string(viewName)
	}
	var peerCount uint16
	binary.Read(r, binary.BigEndian, &peerCount)
	table.PeerEntries = make([]PeerEntry, 0, 16)
	for i := 0; i < int(peerCount); i++ {
		var peerType uint8
		binary.Read(r, binary.LittleEndian, &peerType)
		peerBGPId := make([]byte, 4)
		binary.Read(r, binary.BigEndian, peerBGPId)
		var peerIPAddr []byte
		var peerAS []byte
		switch peerType {
		case 0:
			peerIPAddr = make([]byte, 8)
			peerAS = make([]byte, 2)
			break
		case 1:
			peerIPAddr = make([]byte, 16)
			peerAS = make([]byte, 2)
			break
		case 2:
			peerIPAddr = make([]byte, 8)
			peerAS = make([]byte, 4)
			break
		case 3:
			peerIPAddr = make([]byte, 16)
			peerAS = make([]byte, 4)
			break
		}

		binary.Read(r, binary.BigEndian, peerIPAddr)
		binary.Read(r, binary.BigEndian, peerAS)

		peerEntry := PeerEntry{
			PeerIndex:     i,
			PeerType:      peerType,
			PeerBGPId:     peerBGPId,
			PeerIPAddress: peerIPAddr,
			PeerAS:        0, //TODO: Get real AS number
		}
		table.PeerEntries = append(table.PeerEntries, peerEntry)
	}
	return table
}

func ParseRIBIPV6(r io.Reader) RIBTable {
	table := RIBTable{}
	var header struct {
		SeqNum    uint32
		PrefixLen uint8
	}

	binary.Read(r, binary.BigEndian, &header)

	prefixBytes := header.PrefixLen / 8
	prefix := make([]byte, prefixBytes)
	binary.Read(r, binary.BigEndian, &prefix)
	prefix = append(prefix, make([]byte, 16-prefixBytes)...)

	var entryCount uint16
	binary.Read(r, binary.BigEndian, &entryCount)
	table.RIBEntries = make([]RIBEntry, 0, 8)
	for i := 0; i < int(entryCount); i++ {
		var peerEntry struct {
			PeerIndex      uint16
			OriginatedTime uint32
			AttributeLen   uint16
		}
		binary.Read(r, binary.BigEndian, &peerEntry)

		//bgpAttributeBuffer := make([]byte, peerEntry.AttributeLen)
		bgpAttributeBuffer := bytes.NewBuffer(nil)
		io.CopyN(bgpAttributeBuffer, r, int64(peerEntry.AttributeLen))
		bgpAttributes := ParseBGPAttributes(bgpAttributeBuffer)

		table.RIBEntries = append(table.RIBEntries, RIBEntry{
			PeerIndex:         int(peerEntry.PeerIndex),
			OriginatedTime:    time.Unix(int64(peerEntry.OriginatedTime), 0),
			BGPPathAttributes: bgpAttributes,
		})
	}

	table.SequenceNum = header.SeqNum
	table.PrefixLen = header.PrefixLen
	table.Prefix = prefix

	return table
}

func ParseBGPAttributes(r io.Reader) []BGPAttribute {
	bgpAttributes := make([]BGPAttribute, 0, 4)
	for {
		var header struct {
			AttributeFlag   uint8
			AttributeType   uint8
			AttributeLength uint8
		}
		err := binary.Read(r, binary.BigEndian, &header)
		if err == io.EOF {
			break
		}

		data := make([]byte, header.AttributeLength)
		binary.Read(r, binary.BigEndian, &data)

		bgpAttributes = append(bgpAttributes, BGPAttribute{
			Optional:   header.AttributeFlag&uint8(BGP_ATTR_FLAG_OPTIONAL) == uint8(BGP_ATTR_FLAG_OPTIONAL),
			Transitive: header.AttributeFlag&uint8(BGP_ATTR_FLAG_TRANSITIVE) == uint8(BGP_ATTR_FLAG_TRANSITIVE),
			Partial:    header.AttributeFlag&uint8(BGP_ATTR_FLAG_PARTIAL) == uint8(BGP_ATTR_FLAG_PARTIAL),
			Extended:   header.AttributeFlag&uint8(BGP_ATTR_FLAG_EXTENDED) == uint8(BGP_ATTR_FLAG_EXTENDED),
			Type:       BGPAttributeType(header.AttributeType),
			Data:       data,
		})

	}
	return bgpAttributes
}
