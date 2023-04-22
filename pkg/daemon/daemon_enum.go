// Code generated by go-enum DO NOT EDIT.
// Version: 0.5.5
// Revision: b9e7d1ac24b2b7f6a5b451fa3d21706ffd8d79e2
// Build Date: 2023-01-30T01:49:43Z
// Built By: goreleaser

package daemon

import (
	"errors"
	"fmt"
)

const (
	// DaemonVulnerability is a Daemon of type Vulnerability.
	DaemonVulnerability Daemon = "Vulnerability"
	// DaemonSbom is a Daemon of type Sbom.
	DaemonSbom Daemon = "Sbom"
)

var ErrInvalidDaemon = errors.New("not a valid Daemon")

// String implements the Stringer interface.
func (x Daemon) String() string {
	return string(x)
}

// String implements the Stringer interface.
func (x Daemon) IsValid() bool {
	_, err := ParseDaemon(string(x))
	return err == nil
}

var _DaemonValue = map[string]Daemon{
	"Vulnerability": DaemonVulnerability,
	"Sbom":          DaemonSbom,
}

// ParseDaemon attempts to convert a string to a Daemon.
func ParseDaemon(name string) (Daemon, error) {
	if x, ok := _DaemonValue[name]; ok {
		return x, nil
	}
	return Daemon(""), fmt.Errorf("%s is %w", name, ErrInvalidDaemon)
}
