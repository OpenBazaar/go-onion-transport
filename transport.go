package onion

import (
	"fmt"
	"log"
	"net"

	tpt "github.com/ipfs/go-libp2p-transport"
	ma "github.com/jbenet/go-multiaddr"
	manet "github.com/jbenet/go-multiaddr-net"
	mafmt "github.com/whyrusleeping/mafmt"
	"golang.org/x/net/context"
)

var OnionProtocol = ma.Protocol{
	Code:  444,
	Name:  "onion",
	VCode: ma.CodeToVarint(444),
}

var WsFmt = mafmt.And(mafmt.TCP, mafmt.Base(WsProtocol.Code))

var OnionCodec = &manet.NetCodec{
	NetAddrNetworks:  []string{"onion"},
	ProtocolName:     "onion",
	ConvertMultiaddr: ConvertOnionMultiaddrToNetAddr,
	ParseNetAddr:     ParseOnionNetAddr,
}

func init() {
	err := ma.AddProtocol(OnionProtocol)
	if err != nil {
		log.Fatalf("error registering onion protocol: %s", err)
	}

	manet.RegisterNetCodec(OnionCodec)
}

func ConvertOnionMultiaddrToNetAddr(maddr ma.Multiaddr) (net.Addr, error) {
	// XXX
}

func ParseOnionNetAddr(a net.Addr) (ma.Multiaddr, error) {
	// XXX
}
