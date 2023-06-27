package main

import (
	"errors"
	"strconv"

	"github.com/urfave/cli/v2"
	deserializer "github.com/worldcoin/ptau-deserializer/deserialize"
	"github.com/worldcoin/semaphore-mtb-setup/keys"
	"github.com/worldcoin/semaphore-mtb-setup/phase1"
	"github.com/worldcoin/semaphore-mtb-setup/phase2"
)

func p1t(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 4 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	outputPath := cCtx.Args().Get(1)
	inPowStr := cCtx.Args().Get(2)
	inPower, err := strconv.Atoi(inPowStr)
	if err != nil {
		return err
	}
	outPowStr := cCtx.Args().Get(3)
	outPower, err := strconv.Atoi(outPowStr)
	if err != nil {
		return err
	}
	if inPower < outPower {
		return errors.New("cannot transform to a higher power")
	}
	err = phase1.Transform(inputPath, outputPath, byte(inPower), byte(outPower))
	return err
}

func p1n(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the correct arguments")
	}
	powerStr := cCtx.Args().Get(0)
	power, err := strconv.Atoi(powerStr)
	if err != nil {
		return err
	}
	if power > 26 {
		return errors.New("can't support powers larger than 26")
	}
	outputPath := cCtx.Args().Get(1)
	err = phase1.Initialize(byte(power), outputPath)
	return err
}

func p1c(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	outputPath := cCtx.Args().Get(1)
	err := phase1.Contribute(inputPath, outputPath)
	return err
}

func p1i(cCtx *cli.Context) error {
	ptauFilePath := cCtx.Args().Get(0)
	outputFilePath := cCtx.Args().Get(1)

	ptau, err := deserializer.ReadPtau(ptauFilePath)

	if err != nil {
		return err
	}

	phase1, err := deserializer.ConvertPtauToPhase1(ptau)

	if err != nil {
		return err
	}

	// Write phase1 to file
	err = deserializer.WritePhase1(phase1, uint8(ptau.Header.Power), outputFilePath)

	if err != nil {
		return err
	}

	return nil
}

func p1v(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 1 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	err := phase1.Verify(inputPath, "")
	return err
}

func p1vt(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	transformedPath := cCtx.Args().Get(1)
	err := phase1.Verify(inputPath, transformedPath)
	return err
}

func p2n(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 3 {
		return errors.New("please provide the correct arguments")
	}

	phase1Path := cCtx.Args().Get(0)
	r1csPath := cCtx.Args().Get(1)
	phase2Path := cCtx.Args().Get(2)
	err := phase2.Initialize(phase1Path, r1csPath, phase2Path)
	return err
}

func p2np(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 6 {
		return errors.New("please provide the correct arguments")
	}

	phase1Path := cCtx.Args().Get(0)
	r1csPath := cCtx.Args().Get(1)
	phase2Path := cCtx.Args().Get(2)
	nbCons, err := strconv.Atoi(cCtx.Args().Get(3))
	if err != nil {
		return err
	}

	nbR1C, err := strconv.Atoi(cCtx.Args().Get(4))
	if err != nil {
		return err
	}

	batchSize, err := strconv.Atoi(cCtx.Args().Get(5))
	if err != nil {
		return err
	}

	err = phase2.InitializeFromPartedR1CS(phase1Path, r1csPath, phase2Path, nbCons, nbR1C, batchSize)
	return err
}

func p2c(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	outputPath := cCtx.Args().Get(1)
	err := phase2.Contribute(inputPath, outputPath)
	return err
}

func p2v(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	originPath := cCtx.Args().Get(1)
	err := phase2.Verify(inputPath, originPath)
	return err
}

func extract(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 1 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	err := keys.ExtractKeys(inputPath)
	return err
}

func extracts(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 2 {
		return errors.New("please provide the correct arguments")
	}
	inputPath := cCtx.Args().Get(0)
	session := cCtx.Args().Get(1)
	err := keys.ExtractSplitKeys(inputPath, session)
	return err
}

func exportSol(cCtx *cli.Context) error {
	// sanity check
	if cCtx.Args().Len() != 1 {
		return errors.New("please provide the correct arguments")
	}
	session := cCtx.Args().Get(0)
	err := keys.ExportSol(session)
	return err
}
