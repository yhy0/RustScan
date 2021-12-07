package RustScan

import (
	"errors"
)

var (
	// ErrRustScanNotInstalled means that upon trying to manually locate RustScan in the user's path,
	// it was not found. Either use the WithBinaryPath method to set it manually, or make sure that
	// the RustScan binary is present in the user's $PATH.
	ErrRustScanNotInstalled = errors.New("RustScan binary was not found")

	// ErrScanTimeout means that the provided context was done before the scanner finished its scan.
	ErrScanTimeout = errors.New("RustScan scan timed out")

	// ErrMallocFailed means that RustScan crashed due to insufficient memory, which may happen on large target networks.
	ErrMallocFailed = errors.New("malloc failed, probably out of space")

	// ErrParseOutput means that RustScan's output was not parsed successfully.
	ErrParseOutput = errors.New("unable to parse RustScan output, see warnings for details")

	// ErrResolveName means that RustScan could not resolve a name.
	ErrResolveName = errors.New("RustScan could not resolve a name")
)
