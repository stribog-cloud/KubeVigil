// Package main provides the kubevigil CLI entry point and Cobra command tree.
//
// It exposes the scan, fix, list, and version subcommands for Kubernetes
// Security Posture Management. Run "kubevigil --help" for usage details.
package main

import "os"

func main() {
	os.Exit(execute())
}
