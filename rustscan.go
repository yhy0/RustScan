// Package RustScan provides idiomatic `RustScan` bindings for go developers.
package RustScan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ScanRunner represents something that can run a scan.
type ScanRunner interface {
	Run() (result *Run, warnings []string, err error)
}

// Streamer constantly streams the stdout.
type Streamer interface {
	Write(d []byte) (int, error)
	Bytes() []byte
}

// Scanner represents an RustScan scanner.
type Scanner struct {
	cmd *exec.Cmd

	args       []string
	binaryPath string
	ctx        context.Context

	portFilter func(Port) bool
	hostFilter func(Host) bool

	stderr, stdout bufio.Scanner
}

// Option is a function that is used for grouping of Scanner options.
// Option adds or removes RustScan command line arguments.
type Option func(*Scanner)

// NewScanner creates a new Scanner, and can take options to apply to the scanner.
func NewScanner(options ...Option) (*Scanner, error) {
	scanner := &Scanner{}

	for _, option := range options {
		option(scanner)
	}

	if scanner.binaryPath == "" {
		var err error
		scanner.binaryPath, err = exec.LookPath("rustscan")
		if err != nil {
			return nil, ErrRustScanNotInstalled
		}
	}

	if scanner.ctx == nil {
		scanner.ctx = context.Background()
	}

	return scanner, nil
}

// Run runs RustScan synchronously and returns the result of the scan.
func (s *Scanner) Run(limit int) (result *Run, warnings []string, err error) {
	var (
		stderr bytes.Buffer
		resume         bool
	)

	args := s.args

	for _, arg := range args {
		if arg == "--resume" {
			resume = true
			break
		}
	}

	if !resume {
		args = append(args, "--")
		// Enable XML output
		args = append(args, "-oX")
		// Get XML output in stdout instead of writing it in a file
		args = append(args, "-")
	}

	// Prepare RustScan process
	cmd := exec.Command(s.binaryPath, args...)

	cmdStdoutPipe, _ := cmd.StdoutPipe()

	//cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run RustScan process
	err = cmd.Start()
	if err != nil {
		return nil, warnings, err
	}
	var out_tmp string

	var n int
	// 从管道中实时获取输出并打印到终端
	for {
		tmp := make([]byte, 1024)
		_, err := cmdStdoutPipe.Read(tmp)
		out_tmp += string(tmp)
		if strings.Contains(string(tmp), "Open ") {
			n++
		}
		if err != nil {
			break
		}
	}

	if n > limit {
		// Context was done before the scan was finished.
		// The process is killed and a timeout error is returned.
		_ = cmd.Process.Kill()
		return nil, warnings, ErrScanCDN
	}

	// Make a goroutine to notify the select when the scan is done.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for RustScan process or timeout
	select {
	case <-s.ctx.Done():

		// Context was done before the scan was finished.
		// The process is killed and a timeout error is returned.
		_ = cmd.Process.Kill()
		return nil, warnings, ErrScanTimeout
	case <-done:

		// Process RustScan stderr output containing none-critical errors and warnings
		// Everyone needs to check whether one or some of these warnings is a hard issue in their use case
		if stderr.Len() > 0 {
			warnings = strings.Split(strings.Trim(stderr.String(), "\n"), "\n")
		}

		// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
		if err := analyzeWarnings(warnings); err != nil {
			return nil, warnings, err
		}

		// Parse RustScan xml output. Usually RustScan always returns valid XML, even if there is a scan error.
		// Potentially available warnings are returned too, but probably not the reason for a broken XML.

		var out []byte
		rustscan_info := strings.Split(out_tmp, "[~]")
		for _, info := range rustscan_info {
			if strings.Contains(info, "<?xml ") {
				out = []byte(info[1:])
			} else if strings.Contains(info, "Looks like I didn't find any open ports") {
				//todo 扫描结果中没有扫出开放端口时，这里直接构造了一个 nmap 扫描结果的 xml 格式字符串，毕竟不关心关闭的端口，输出不对无关紧要,
				out = Structure()
			}
		}

		result, err := Parse(out)
		if err != nil {
			warnings = append(warnings, err.Error()) // Append parsing error to warnings for those who are interested.
			return nil, warnings, ErrParseOutput
		}

		// Critical scan errors are reflected in the XML.
		if result != nil && len(result.Stats.Finished.ErrorMsg) > 0 {
			switch {
			case strings.Contains(result.Stats.Finished.ErrorMsg, "Error resolving name"):
				return result, warnings, ErrResolveName
			// TODO: Add cases for other known errors we might want to guard.
			default:
				return result, warnings, fmt.Errorf(result.Stats.Finished.ErrorMsg)
			}
		}

		// Call filters if they are set.
		if s.portFilter != nil {
			result = choosePorts(result, s.portFilter)
		}
		if s.hostFilter != nil {
			result = chooseHosts(result, s.hostFilter)
		}

		// Return result, optional warnings but no error
		return result, warnings, nil
	}
}

// Wait waits for the cmd to finish and returns error.
func (s *Scanner) Wait() error {
	return s.cmd.Wait()
}

// GetStdout returns stdout variable for scanner.
func (s *Scanner) GetStdout() bufio.Scanner {
	return s.stdout
}

// GetStderr returns stderr variable for scanner.
func (s *Scanner) GetStderr() bufio.Scanner {
	return s.stderr
}

// AddOptions sets more scan options after the scan is created.
func (s *Scanner) AddOptions(options ...Option) {
	for _, option := range options {
		option(s)
	}
}

func chooseHosts(result *Run, filter func(Host) bool) *Run {
	var filteredHosts []Host

	for _, host := range result.Hosts {
		if filter(host) {
			filteredHosts = append(filteredHosts, host)
		}
	}

	result.Hosts = filteredHosts

	return result
}

func choosePorts(result *Run, filter func(Port) bool) *Run {
	for idx := range result.Hosts {
		var filteredPorts []Port

		for _, port := range result.Hosts[idx].Ports {
			if filter(port) {
				filteredPorts = append(filteredPorts, port)
			}
		}

		result.Hosts[idx].Ports = filteredPorts
	}

	return result
}

func analyzeWarnings(warnings []string) error {
	// Check for warnings that will inevitably lead to parsing errors, hence, have priority.
	for _, warning := range warnings {
		switch {
		case strings.Contains(warning, "Malloc Failed!"):
			return ErrMallocFailed
		// TODO: Add cases for other known errors we might want to guard.
		default:
		}
	}
	return nil
}

// WithContext adds a context to a scanner, to make it cancellable and able to timeout.
func WithContext(ctx context.Context) Option {
	return func(s *Scanner) {
		s.ctx = ctx
	}
}

// WithBinaryPath sets the RustScan binary path for a scanner.
func WithBinaryPath(binaryPath string) Option {
	return func(s *Scanner) {
		s.binaryPath = binaryPath
	}
}

// WithCustomArguments sets custom arguments to give to the RustScan binary.
// There should be no reason to use this, unless you are using a custom build
// of RustScan or that this repository isn't up to date with the latest options
// of the official RustScan release.
// You can use this as a quick way to paste an RustScan command into your go code,
// but remember that the whole purpose of this repository is to be idiomatic,
// provide type checking, enums for the values that can be passed, etc.
func WithCustomArguments(args ...string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, args...)
	}
}

// WithFilterPort allows to set a custom function to filter out ports that
// don't fulfill a given condition. When the given function returns true,
// the port is kept, otherwise it is removed from the result. Can be used
// along with WithFilterHost.
func WithFilterPort(portFilter func(Port) bool) Option {
	return func(s *Scanner) {
		s.portFilter = portFilter
	}
}

// WithFilterHost allows to set a custom function to filter out hosts that
// don't fulfill a given condition. When the given function returns true,
// the host is kept, otherwise it is removed from the result. Can be used
// along with WithFilterPort.
func WithFilterHost(hostFilter func(Host) bool) Option {
	return func(s *Scanner) {
		s.hostFilter = hostFilter
	}
}

/*** Target specification ***/

// WithTargets sets the target of a scanner.
func WithTargets(targets ...string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-a")
		s.args = append(s.args, targets...)
	}
}

// TCPFlag represents a TCP flag.
type TCPFlag int

/*** Port specification and scan order ***/

// WithPorts sets the ports which the scanner should scan on each host.
func WithPorts(ports ...string) Option {
	portList := strings.Join(ports, ",")

	var elems string
	if strings.Contains(portList, ",") {
		elems = "-p"
	} else {
		elems = "-r"
	}

	return func(s *Scanner) {
		// Find if any port is set.
		var place int = -1
		for p, value := range s.args {
			if value == "-p" {
				place = p
				break
			}
		}

		// Add ports.
		if place >= 0 {
			portList = s.args[place+1] + "," + portList
			s.args[place+1] = portList
		} else {
			s.args = append(s.args, elems)
			s.args = append(s.args, portList)
		}
	}
}


// WithbatchSize The batch size for port scanning, it increases or slows the speed of scanning.
// Depends on the open file limit of your OS.  If you do 65535 it will do every port
// at the same time. Although, your OS may not support this [default: 4500]
func WithBatchSize(size int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-b")
		s.args = append(s.args, fmt.Sprint(size))
	}
}

// The timeout in milliseconds before a port is assumed to be closed [default: 1500]
func WithTimeout(number int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-t")
		s.args = append(s.args, fmt.Sprint(number))
	}
}

// The order of scanning to be performed. The "serial" option will scan ports in
//  ascending order while the "random" option will scan ports randomly [default:
//  serial]  [possible values: Serial, Random]
func WithScanOrder(order string) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "--scan-order")
		s.args = append(s.args, order)
	}
}

// WithUlimit  Automatically ups the ULIMIT with the value you provided
func WithUlimit(ulimit int) Option {
	return func(s *Scanner) {
		s.args = append(s.args, "-u")
		s.args = append(s.args, fmt.Sprint(ulimit))
	}
}


// ReturnArgs return the list of RustScan args
func (s *Scanner) Args() []string {
	return s.args
}

func Structure() []byte {
	close_info := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.92 scan initiated Tue Dec  7 15:34:04 2021 as: nmap -p 80,443 -oX - rustscan_info -->
<nmaprun scanner="nmap" args="nmap -p 80,443 -oX - rustscan_info" start="1638862444" startstr="Tue Dec  7 15:34:04 2021" version="7.92" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="2" services="80,443"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="rustscan_info" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1638862444" endtime="1638862444"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="rustscan_info" addrtype="ipv4"/>
<hostnames>
</hostnames>
<ports><port protocol="tcp" portid="80"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="http" method="table" conf="3"/></port>
</ports>
<times srtt="53510" rttvar="31142" to="178078"/>
</host>
<runstats><finished time="1638862444" timestr="Tue Dec  7 15:34:04 2021" summary="Nmap done at Tue Dec  7 15:34:04 2021; 1 IP address (1 host up) scanned in 0.25 seconds" elapsed="0.25" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>`

	close_info = strings.ReplaceAll(close_info, "rustscan_info", "www.baidu.com")

	return []byte(close_info)
}

