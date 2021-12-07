package main

import (
	"context"
	"fmt"
	"github.com/yhy0/RustScan"
	"log"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/RustScan -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	scanner, err := RustScan.NewScanner(
		RustScan.WithTargets("baidu.com"),
		RustScan.WithPorts("80,443,843,22"),
		RustScan.WithContext(ctx),
	)
	if err != nil {
		log.Fatalf("unable to create RustScan scanner: %v", err)
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run RustScan scan: %v", err)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("RustScan done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
