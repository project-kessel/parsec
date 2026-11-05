// Package buildinfo holds metadata injected by the build.
package buildinfo

// Version is replaced with the release/tag or commit by the linker.
var Version = "development"

// Commit is replaced with the source revision by the linker.
var Commit = "unknown"
