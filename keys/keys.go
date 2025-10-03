package keys

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/worldcoin/semaphore-mtb-setup/phase2"
)

type VerifyingKey struct {
	G1 struct {
		Alpha       bn254.G1Affine
		Beta, Delta bn254.G1Affine   // unused, here for compatibility purposes
		K           []bn254.G1Affine // The indexes correspond to the public wires
	}

	G2 struct {
		Beta, Delta, Gamma bn254.G2Affine
	}

	CommitmentKey  pedersen.VerifyingKey
	CommitmentInfo constraint.Commitment // since the verifier doesn't input a constraint system, this needs to be provided here
}

func (vk *VerifyingKey) writeTo(w io.Writer) (int64, error) {
	enc := bn254.NewEncoder(w, bn254.RawEncoding())

	// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2
	if err := enc.Encode(&vk.G1.Alpha); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Beta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Beta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Gamma); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Delta); err != nil {
		return enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Delta); err != nil {
		return enc.BytesWritten(), err
	}

	// uint32(len(Kvk)),[Kvk]1
	if err := enc.Encode(vk.G1.K); err != nil {
		return enc.BytesWritten(), err
	}

	return enc.BytesWritten(), nil
}

func extractPK(phase2Path string) error {
	// Derive evals file path from phase2Path
	evalsPath := phase2Path[:len(phase2Path)-4] + ".evals"

	// Phase 2 file
	phase2File, err := os.Open(phase2Path)
	if err != nil {
		return err
	}
	defer phase2File.Close()

	// Evaluations
	evalsFile, err := os.Open(evalsPath)
	if err != nil {
		return err
	}
	defer evalsFile.Close()

	// Use buffered IO to read parameters efficiently
	ph2Reader := bufio.NewReader(phase2File)
	evalsReader := bufio.NewReader(evalsFile)

	var header phase2.Header
	if err := header.Read(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	// Create gnark ProvingKey structure (concrete type, not interface)
	pk := &groth16bn254.ProvingKey{}

	var alphaG1, betaG1, deltaG1 bn254.G1Affine
	var betaG2, deltaG2 bn254.G2Affine

	// Set domain
	pk.Domain = *fft.NewDomain(uint64(header.Domain))

	// 1. Read [α]₁
	if err := decEvals.Decode(&alphaG1); err != nil {
		return err
	}

	// 2. Read [β]₁
	if err := decEvals.Decode(&betaG1); err != nil {
		return err
	}

	// 3. Read [δ]₁
	if err := decPh2.Decode(&deltaG1); err != nil {
		return err
	}

	// Read [β]₂
	if err := decEvals.Decode(&betaG2); err != nil {
		return err
	}
	// Read [δ]₂
	if err := decPh2.Decode(&deltaG2); err != nil {
		return err
	}

	// 4. Read, Filter A
	var buffG1 []bn254.G1Affine
	if err := decEvals.Decode(&buffG1); err != nil {
		return err
	}
	buffG1, infinityA, nbInfinityA := filterInfinityG1(buffG1)

	// 5. Read, Filter B
	var buffG1B []bn254.G1Affine
	if err := decEvals.Decode(&buffG1B); err != nil {
		return err
	}
	buffG1B, infinityB, nbInfinityB := filterInfinityG1(buffG1B)

	// 6. Read Z
	// gnark's Setup creates Z with size Domain-1
	buffG1Z := make([]bn254.G1Affine, header.Domain-1)
	for i := 0; i < header.Domain-1; i++ {
		if err := decPh2.Decode(&buffG1Z[i]); err != nil {
			return err
		}
	}
	// Skip the last Z element that ceremony has but gnark doesn't use
	var skipZ bn254.G1Affine
	if err := decPh2.Decode(&skipZ); err != nil {
		return err
	}

	// 7. Read PKK
	buffG1K := make([]bn254.G1Affine, header.Witness)
	for i := 0; i < header.Witness; i++ {
		if err := decPh2.Decode(&buffG1K[i]); err != nil {
			return err
		}
	}

	// 10. Read B₂
	var buffG2 []bn254.G2Affine
	if err := decEvals.Decode(&buffG2); err != nil {
		return err
	}
	buffG2, _, _ = filterInfinityG2(buffG2)

	// 11. Read commitment key data (like in extractVK)
	// Skip to commitment key position
	pos := int64(128*(header.Wires+1) + 12)
	if _, err := evalsFile.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	evalsReader.Reset(evalsFile)
	decEvals = bn254.NewDecoder(evalsReader)

	// Skip VKK
	var vkKTemp []bn254.G1Affine
	if err := decEvals.Decode(&vkKTemp); err != nil {
		return err
	}

	// Read CKK (Commitment Key)
	var ckk []bn254.G1Affine
	if err := decEvals.Decode(&ckk); err != nil {
		return err
	}

	// Populate gnark ProvingKey structure with filtered arrays
	// gnark expects filtered arrays, NOT full arrays!
	pk.G1.Alpha.Set(&alphaG1)
	pk.G1.Beta.Set(&betaG1)
	pk.G1.Delta.Set(&deltaG1)
	pk.G1.A = buffG1  // Filtered array (no infinity points)
	pk.G1.B = buffG1B // Filtered array (no infinity points)
	pk.G1.Z = buffG1Z
	pk.G1.K = buffG1K

	pk.G2.Beta.Set(&betaG2)
	pk.G2.Delta.Set(&deltaG2)
	pk.G2.B = buffG2 // Filtered array (no infinity points)

	// Set infinity masks
	pk.InfinityA = infinityA
	pk.InfinityB = infinityB
	pk.NbInfinityA = nbInfinityA
	pk.NbInfinityB = nbInfinityB
	pk.CommitmentKeys = []pedersen.ProvingKey{} // No commitments for our circuits

	// Write to file using gnark's standard WriteTo method
	pkFile, err := os.Create("pk")
	if err != nil {
		return err
	}
	defer pkFile.Close()

	// Use WriteTo for compressed format (standard)
	_, err = pk.WriteTo(pkFile)
	return err
}

func extractVK(phase2Path string) error {
	// Derive evals file path from phase2Path
	evalsPath := phase2Path[:len(phase2Path)-4] + ".evals"

	// Phase 2 file
	phase2File, err := os.Open(phase2Path)
	if err != nil {
		return err
	}
	defer phase2File.Close()

	// Evaluations
	evalsFile, err := os.Open(evalsPath)
	if err != nil {
		return err
	}
	defer evalsFile.Close()

	// Use buffered IO to read parameters efficiently
	ph2Reader := bufio.NewReader(phase2File)
	evalsReader := bufio.NewReader(evalsFile)

	var header phase2.Header
	if err := header.Read(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	// Create gnark VerifyingKey structure (concrete type, not interface)
	vk := &groth16bn254.VerifyingKey{}

	var alphaG1, betaG1, deltaG1 bn254.G1Affine
	var betaG2, deltaG2 bn254.G2Affine

	// 1. Read [α]₁
	if err := decEvals.Decode(&alphaG1); err != nil {
		return err
	}

	// 2. Read [β]₁
	if err := decEvals.Decode(&betaG1); err != nil {
		return err
	}

	// 3. Read [β]₂
	if err := decEvals.Decode(&betaG2); err != nil {
		return err
	}

	// 4. Set [γ]₂
	_, _, _, gammaG2 := bn254.Generators()

	// 5. Read [δ]₁
	if err := decPh2.Decode(&deltaG1); err != nil {
		return err
	}

	// 6. Read [δ]₂
	if err := decPh2.Decode(&deltaG2); err != nil {
		return err
	}

	// 7. Read VKK
	pos := int64(128*(header.Wires+1) + 12)
	if _, err := evalsFile.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	evalsReader.Reset(evalsFile)
	var vkK []bn254.G1Affine
	if err := decEvals.Decode(&vkK); err != nil {
		return err
	}

	// 8. Read and setup commitment keys to match R1CS structure
	var ckk []bn254.G1Affine
	if err := decEvals.Decode(&ckk); err != nil {
		return err
	}

	// Setup commitment keys to match R1CS structure
	var commitmentKey pedersen.VerifyingKey
	if len(ckk) > 0 {
		// Convert to [][]G1Affine format expected by pedersen.Setup
		ckkSlices := [][]bn254.G1Affine{ckk}
		_, commitmentKey, err = pedersen.Setup(ckkSlices)
		if err != nil {
			return err
		}
	}

	// Populate gnark VerifyingKey
	vk.G1.Alpha.Set(&alphaG1)
	vk.G1.Beta.Set(&betaG1)
	vk.G1.Delta.Set(&deltaG1)
	vk.G1.K = vkK

	vk.G2.Beta.Set(&betaG2)
	vk.G2.Delta.Set(&deltaG2)
	vk.G2.Gamma.Set(&gammaG2)

	// Set CommitmentKeys to match R1CS structure
	if len(ckk) > 0 {
		vk.CommitmentKeys = []pedersen.VerifyingKey{commitmentKey}
	}

	// Write to file in gnark's standard binary format
	vkFile, err := os.Create("vk")
	if err != nil {
		return err
	}
	defer vkFile.Close()

	// Write using WriteTo (compressed format, standard)
	_, err = vk.WriteTo(vkFile)
	return err
}

func ExtractKeys(phase2Path string) error {
	fmt.Println("Extracting proving key")
	if err := extractPK(phase2Path); err != nil {
		return err
	}
	fmt.Println("Extracting verifying key")
	if err := extractVK(phase2Path); err != nil {
		return err
	}
	fmt.Println("Keys have been extracted successfully")
	return nil
}

func ExportSol(session string) error {
	filename := session + ".sol"
	fmt.Printf("Exporting %s\n", filename)
	f, _ := os.Open(session + ".vk.save")
	verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
	_, err := verifyingKey.ReadFrom(f)
	if err != nil {
		panic(fmt.Errorf("read file error"))
	}
	err = f.Close()
	f, err = os.Create(filename)
	if err != nil {
		panic(err)
	}
	err = verifyingKey.ExportSolidity(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s has been extracted successfully\n", filename)
	return nil
}

func filterInfinityG1(buff []bn254.G1Affine) ([]bn254.G1Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G1Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)
}

// reconstructG1WithInfinity reconstructs the full array from filtered array and infinity mask
// This is the inverse of filterInfinityG1
func reconstructG1WithInfinity(filtered []bn254.G1Affine, infinityMask []bool) []bn254.G1Affine {
	full := make([]bn254.G1Affine, len(infinityMask))
	j := 0
	for i := range infinityMask {
		if infinityMask[i] {
			// Leave as infinity (zero value)
			full[i].X.SetZero()
			full[i].Y.SetZero()
		} else {
			if j < len(filtered) {
				full[i] = filtered[j]
				j++
			}
		}
	}
	return full
}

func filterInfinityG2(buff []bn254.G2Affine) ([]bn254.G2Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G2Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)
}

// reconstructG2WithInfinity reconstructs the full array from filtered array and infinity mask
func reconstructG2WithInfinity(filtered []bn254.G2Affine, infinityMask []bool) []bn254.G2Affine {
	full := make([]bn254.G2Affine, len(infinityMask))
	j := 0
	for i := range infinityMask {
		if infinityMask[i] {
			// Leave as infinity (zero value)
			full[i].X.A0.SetZero()
			full[i].X.A1.SetZero()
			full[i].Y.A0.SetZero()
			full[i].Y.A1.SetZero()
		} else {
			if j < len(filtered) {
				full[i] = filtered[j]
				j++
			}
		}
	}
	return full
}
