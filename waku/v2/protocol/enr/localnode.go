package enr

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"net"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/multiformats/go-multiaddr"
	"go.uber.org/zap"
)

func NewLocalnode(priv *ecdsa.PrivateKey) (*enode.LocalNode, error) {
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, err
	}
	return enode.NewLocalNode(db, priv), nil
}

type ENROption func(*enode.LocalNode) error

func WithMultiaddress(multiaddrs ...multiaddr.Multiaddr) ENROption {
	return func(localnode *enode.LocalNode) (err error) {
		if len(multiaddrs) == 0 {
			return nil
		}

		// Randomly shuffle multiaddresses
		rand.Shuffle(len(multiaddrs), func(i, j int) { multiaddrs[i], multiaddrs[j] = multiaddrs[j], multiaddrs[i] })

		// Find the maximum number of multiaddresses that fit in the ENR size limit
		maxFittingCount := findMaxFittingMultiaddrs(localnode, multiaddrs)
		if maxFittingCount == 0 {
			return errors.New("no multiaddress fit into ENR")
		}

		writeMultiaddressField(localnode, multiaddrs[0:maxFittingCount])
		return nil
	}
}

// findMaxFittingMultiaddrs determines how many multiaddresses can fit in the ENR
func findMaxFittingMultiaddrs(localnode *enode.LocalNode, multiaddrs []multiaddr.Multiaddr) int {
	privk, err := crypto.GenerateKey()
	if err != nil {
		return 0
	}

	// Get the current committed record (after the Node() call above)
	currentRecord := localnode.Node().Record()

	// Binary search for optimal count
	maxFitting := 0

	for i := len(multiaddrs); i > 0; i-- {
		if canFitMultiaddrsOnRecord(currentRecord, multiaddrs[0:i], privk, localnode.Seq()) {
			// Return as soon as we can fit most of the addresses
			return i
		}
	}

	return maxFitting
}

// canFitMultiaddrsOnRecord tests if multiaddresses can fit on a specific record.
// ENR has a limit of 300 bytes. Later it will panic on signing, if the record is over the size limit.
// By simulating what the localnode does when signing the enr, but without causing a panic.
func canFitMultiaddrsOnRecord(baseRecord *enr.Record, addrs []multiaddr.Multiaddr, privk *ecdsa.PrivateKey, seq uint64) bool {
	// Create a copy of the base record
	testRecord := *baseRecord

	// Add the multiaddress field
	testRecord.Set(enr.WithEntry(MultiaddrENRField, marshalMultiaddress(addrs)))
	testRecord.SetSeq(seq + 1)

	// Try to sign - this will return an error if the record is too large
	return enode.SignV4(&testRecord, privk) == nil
}

func WithWakuBitfield(flags WakuEnrBitfield) ENROption {
	return func(localnode *enode.LocalNode) (err error) {
		localnode.Set(enr.WithEntry(WakuENRField, flags))
		return nil
	}
}

func WithIP(ipAddr *net.TCPAddr) ENROption {
	return func(localnode *enode.LocalNode) (err error) {
		if ipAddr.Port == 0 {
			return ErrNoPortAvailable
		}

		localnode.SetStaticIP(ipAddr.IP)
		localnode.Set(enr.TCP(uint16(ipAddr.Port))) // TODO: ipv6?
		return nil
	}
}

func WithUDPPort(udpPort uint) ENROption {
	return func(localnode *enode.LocalNode) (err error) {
		if udpPort == 0 {
			return nil
		}

		if udpPort > math.MaxUint16 {
			return errors.New("invalid udp port number")
		}
		localnode.SetFallbackUDP(int(udpPort))
		return nil
	}
}

func Update(logger *zap.Logger, localnode *enode.LocalNode, enrOptions ...ENROption) error {
	for _, opt := range enrOptions {
		err := opt(localnode)
		if err != nil {
			if errors.Is(err, ErrNoPortAvailable) {
				logger.Warn("no tcp port available. ENR will not contain tcp key")
			} else {
				return err
			}
		}
	}
	return nil
}

func marshalMultiaddress(addrAggr []multiaddr.Multiaddr) []byte {
	var fieldRaw []byte
	for _, addr := range addrAggr {
		maRaw := addr.Bytes()
		maSize := make([]byte, 2)
		binary.BigEndian.PutUint16(maSize, uint16(len(maRaw)))

		fieldRaw = append(fieldRaw, maSize...)
		fieldRaw = append(fieldRaw, maRaw...)
	}
	return fieldRaw
}

func writeMultiaddressField(localnode *enode.LocalNode, addrAggr []multiaddr.Multiaddr) {
	fieldRaw := marshalMultiaddress(addrAggr)
	localnode.Set(enr.WithEntry(MultiaddrENRField, fieldRaw))
}

func DeleteField(localnode *enode.LocalNode, field string) {
	localnode.Delete(enr.WithEntry(field, struct{}{}))
}
