package pvss

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/Xieyangxinyu/380D/common"
	"github.com/Xieyangxinyu/380D/secp256k1"
)

type nodeList struct {
	Nodes []common.Node
}

func createRandomNodes(number int) (*nodeList, []big.Int) {
	list := new(nodeList)
	privateKeys := make([]big.Int, number)
	for i := 0; i < number; i++ {
		pkey := RandomBigInt()
		list.Nodes = append(list.Nodes, common.Node{
			i + 1,
			common.BigIntToPoint(secp256k1.Curve.ScalarBaseMult(pkey.Bytes())),
			false,
		})
		privateKeys[i] = *pkey
	}
	return list, privateKeys
}

func TestBeacon(test *testing.T) {

	// Set the number of nodes in the distributed network
	numberOfNodes := 64
	threshold := numberOfNodes/2 + 1
	time_threshold := 72.0
	exp_mean := float64(numberOfNodes)

	// Set up
	// type Node struct {
    // Index  int
	// PubKey Point
    //}
	nodeList, privateKeys := createRandomNodes(numberOfNodes)
	
	secrets := make([]big.Int, len(nodeList.Nodes))
	secret := new(big.Int)
	for i:= range secrets{
		secrets[i] = *RandomBigInt()
		secret.Add(secret, &secrets[i])
	}
	secret.Mod(secret, secp256k1.GeneratorOrder)
	
	// Commitment Phase
	errorsExist := false
	allSigncryptedShares := make([][]*common.SigncryptedOutput, len(nodeList.Nodes))
	allPubPoly := make([][]common.Point, len(nodeList.Nodes))

	failed_nodes := 0
	waiting_time := make([]float64, len(nodeList.Nodes))
	
	for i := range nodeList.Nodes {
		// Deal
		t1 := time.Now()
		signcryptedShares, pubPoly, err := CreateAndPrepareShares(nodeList.Nodes, secrets[i], threshold, privateKeys[i])
		allSigncryptedShares[i] = signcryptedShares
		allPubPoly[i] = *pubPoly
		if err != nil {
			fmt.Println(err)
			errorsExist = true
		}
		t2 := time.Now()
		diff := t2.Sub(t1)
		waiting_time[i] = rand.ExpFloat64() * exp_mean + diff.Seconds() * 1000
	}

	// Reveal Phase
	allDecryptedShares := make([][]big.Int, len(nodeList.Nodes))
	
	for i := range nodeList.Nodes {
		// Decrypt and Verify
		// Verify is within the UnsigncryptShare function

		t1 := time.Now()
		arrDecryptShares := make([]big.Int, len(nodeList.Nodes))
		for j := range nodeList.Nodes {
			decryptedShare, err := UnsigncryptShare(allSigncryptedShares[j][i].SigncryptedShare, privateKeys[i], nodeList.Nodes[j].PubKey)
			temp := new(big.Int).SetBytes(*decryptedShare)
			if err != nil {
				fmt.Println(err)
				errorsExist = true
			}
			arrDecryptShares[j] = *temp
		}
		allDecryptedShares[i] = arrDecryptShares
		t2 := time.Now()
		diff := t2.Sub(t1)
		waiting_time[i] += diff.Seconds() * 1000
	}


	// Recover
	//form si, points on the polynomial f(z) = r + a1z + a2z^2....
	allSi := make([]common.PrimaryShare, len(nodeList.Nodes))
	
	for i := range nodeList.Nodes {
		sum := new(big.Int)
		for j := range nodeList.Nodes {
			sum.Add(sum, &allDecryptedShares[i][j])
		}
		sum.Mod(sum, secp256k1.GeneratorOrder)
		allSi[i] = common.PrimaryShare{i + 1, *sum}
		if waiting_time[i] > time_threshold{
			failed_nodes += 1
		}
	}

	// For simplicity, we assume the last few nodes are the failed nodes
	deltas := Recover(allSi[:numberOfNodes - failed_nodes], 0)
	
	testr := new(big.Int)
	
	for i := range deltas{
		testr.Add(testr, deltas[i])
	}
	testr.Mod(testr, secp256k1.GeneratorOrder)

	fmt.Printf("%d nodes failed!\n", failed_nodes)
	assert.True(test, testr.Cmp(secret) == 0)


	assert.False(test, errorsExist)
}