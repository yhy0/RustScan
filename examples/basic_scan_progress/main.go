package main

import (
	"fmt"
	"github.com/yhy0/RustScan"
	"log"
)

func main() {
	scanner, err := RustScan.NewScanner(
		RustScan.WithTargets("localhost"),
		RustScan.WithPorts("1-4000"),
		RustScan.WithServiceInfo(),
		RustScan.WithVerbosity(3),
	)
	if err != nil {
		log.Fatalf("unable to create RustScan scanner: %v", err)
	}

	progress := make(chan float32, 1)

	// Function to listen and print the progress
	go func() {
		for p := range progress {
			fmt.Printf("Progress: %v %%\n", p)
		}
	}()

	result, _, err := scanner.RunWithProgress(progress)
	if err != nil {
		log.Fatalf("unable to run RustScan scan: %v", err)
	}

	fmt.Printf("RustScan done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
