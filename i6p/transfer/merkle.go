package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var (
	ErrMerkleEmpty      = errors.New("merkle: no chunks provided")
	ErrMerkleProofFail  = errors.New("merkle: proof verification failed")
	ErrMerkleIndexRange = errors.New("merkle: chunk index out of range")
)

// MerkleTree provides integrity verification for chunked data.
// The root hash can be shared before transfer; recipients verify each chunk.
type MerkleTree struct {
	leaves [][]byte
	nodes  [][]byte // full binary tree stored as array
	root   []byte
}

// BuildMerkleTree constructs a Merkle tree from chunk hashes.
// Each chunk should be hashed with SHA-256 before passing here.
func BuildMerkleTree(chunkHashes [][]byte) (*MerkleTree, error) {
	if len(chunkHashes) == 0 {
		return nil, ErrMerkleEmpty
	}

	// Pad to power of 2
	n := 1
	for n < len(chunkHashes) {
		n *= 2
	}
	leaves := make([][]byte, n)
	for i := range leaves {
		if i < len(chunkHashes) {
			leaves[i] = chunkHashes[i]
		} else {
			// Pad with hash of empty
			h := sha256.Sum256(nil)
			leaves[i] = h[:]
		}
	}

	// Build tree bottom-up
	nodes := make([][]byte, 2*n-1)
	// Leaves are at positions [n-1, 2n-2]
	for i, leaf := range leaves {
		nodes[n-1+i] = leaf
	}
	// Internal nodes
	for i := n - 2; i >= 0; i-- {
		left := nodes[2*i+1]
		right := nodes[2*i+2]
		combined := append(left, right...)
		h := sha256.Sum256(combined)
		nodes[i] = h[:]
	}

	return &MerkleTree{
		leaves: leaves,
		nodes:  nodes,
		root:   nodes[0],
	}, nil
}

// Root returns the Merkle root hash.
func (m *MerkleTree) Root() []byte { return m.root }

// RootHex returns the Merkle root as a hex string.
func (m *MerkleTree) RootHex() string { return hex.EncodeToString(m.root) }

// Proof generates a Merkle proof for the chunk at the given index.
// Returns the sibling hashes needed to verify the chunk.
type Proof struct {
	ChunkIndex int
	ChunkHash  []byte
	Siblings   [][]byte // from leaf to root
	IsLeft     []bool   // true if sibling is on the left
}

func (m *MerkleTree) GenerateProof(chunkIndex int) (Proof, error) {
	n := len(m.leaves)
	if chunkIndex < 0 || chunkIndex >= n {
		return Proof{}, ErrMerkleIndexRange
	}

	var siblings [][]byte
	var isLeft []bool
	idx := n - 1 + chunkIndex // position in nodes array

	for idx > 0 {
		parentIdx := (idx - 1) / 2
		var siblingIdx int
		if idx%2 == 1 {
			siblingIdx = idx + 1
		} else {
			siblingIdx = idx - 1
		}
		siblings = append(siblings, m.nodes[siblingIdx])
		isLeft = append(isLeft, idx%2 == 0)
		idx = parentIdx
	}

	return Proof{
		ChunkIndex: chunkIndex,
		ChunkHash:  m.leaves[chunkIndex],
		Siblings:   siblings,
		IsLeft:     isLeft,
	}, nil
}

// VerifyProof verifies a Merkle proof against the expected root.
func VerifyProof(proof Proof, expectedRoot []byte) error {
	current := proof.ChunkHash
	for i, sibling := range proof.Siblings {
		var combined []byte
		if proof.IsLeft[i] {
			combined = append(sibling, current...)
		} else {
			combined = append(current, sibling...)
		}
		h := sha256.Sum256(combined)
		current = h[:]
	}

	if !bytesEqual(current, expectedRoot) {
		return ErrMerkleProofFail
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// HashChunk computes the SHA-256 hash of a data chunk.
func HashChunk(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
