package bls

import (
	"crypto/sha256"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kilic/bn254"
)

type Hasher interface {
	Hash(message *Message) (*PointG1, error)
}

type HasherSHA256 struct {
	mapper *bn254.G1
}

type HasherKeccak256 struct {
	mapper *bn254.G1
}

func (h *HasherSHA256) Hash(message *Message) (*PointG1, error) {
	mapper := h.mapper
	if mapper == nil {
		mapper = bn254.NewG1()
	}
	H := sha256.New()
	_, _ = H.Write(message.Domain)
	_, _ = H.Write(message.Message)
	digest := H.Sum(nil)
	return mapper.MapToPointTI(digest)
}

func (h *HasherKeccak256) Hash(message *Message) (*PointG1, error) {
	mapper := h.mapper
	if mapper == nil {
		mapper = bn254.NewG1()
	}
	digest := crypto.Keccak256(message.Domain, message.Message)
	return mapper.MapToPointTI(digest)
}
