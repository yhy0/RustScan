# RustScan

根据 https://github.com/Ullaakut/nmap 改造的 调用 rustscan 进行端口扫描的 go 包

需要安装 RustScan 和 nmap 

https://github.com/RustScan/RustScan
https://github.com/nmap/nmap

RustScan 快速筛选开放的端口，然后调用 nmap 进行服务识别 
和 masscan + nmap 联合调用效果一样，不过该项目的有点在于RustScan会自动调用 nmap 进行识别
并且如果 rustscan 先扫出的端口个数大于一定的值(用户传入),则判断存在 cdn ，不再调用 nmap 扫描

## Simple example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/yhy0/RustScan"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // Equivalent to `/usr/local/bin/RustScan -p 80,443,843 google.com facebook.com youtube.com`,
    // with a 5 minute timeout.
    scanner, err := RustScan.NewScanner(
        RustScan.WithTargets("google.com", "facebook.com", "youtube.com"),
        RustScan.WithPorts("80,443,843"),
        RustScan.WithContext(ctx),
    )
    if err != nil {
        log.Fatalf("unable to create RustScan scanner: %v", err)
    }
	// 传入一个 limit ，如果 rustscan 先扫出的端口大于 传入的值，则判断存在 cdn，就不在调用 nmap 识别
    result, warnings, err := scanner.Run(30)
    if err != nil {
        log.Fatalf("unable to run RustScan scan: %v", err)
    }

    if warnings != nil {
        log.Printf("Warnings: \n %v", warnings)
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

    fmt.Printf("RustScan done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
```

The program above outputs:

```bash
Host "172.217.16.46":
    Port 80/tcp open http
    Port 443/tcp open https
    Port 843/tcp filtered unknown
Host "31.13.81.36":
    Port 80/tcp open http
    Port 443/tcp open https
    Port 843/tcp open unknown
Host "216.58.215.110":
    Port 80/tcp open http
    Port 443/tcp open https
    Port 843/tcp filtered unknown
RustScan done: 3 hosts up scanned in 1.29 seconds
```
