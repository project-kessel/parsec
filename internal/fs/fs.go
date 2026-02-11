package fs

import (
	"io/fs"
	"os"
	"path/filepath"
)

// FileSystem is a minimal filesystem abstraction for key storage operations.
// It provides the operations needed for atomic file writes and reads.
type FileSystem interface {
	// MkdirAll creates a directory and all necessary parents
	MkdirAll(path string, perm fs.FileMode) error

	// ReadFile reads the entire file
	ReadFile(name string) ([]byte, error)

	// WriteFileAtomic writes data to a file atomically
	// The write is atomic - either all data is written or none
	// For OS filesystems, this uses temp file + sync + rename
	// For in-memory filesystems, this can be a direct write
	WriteFileAtomic(name string, data []byte, perm fs.FileMode) error

	// IsNotExist returns true if the error indicates a file doesn't exist
	IsNotExist(err error) bool
}

// OSFileSystem is a FileSystem implementation using the real OS filesystem.
type OSFileSystem struct{}

// NewOSFileSystem creates a new OS filesystem
func NewOSFileSystem() *OSFileSystem {
	return &OSFileSystem{}
}

// MkdirAll creates a directory and all necessary parents
func (f *OSFileSystem) MkdirAll(path string, perm fs.FileMode) error {
	return os.MkdirAll(path, perm)
}

// ReadFile reads the entire file
func (f *OSFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

// WriteFileAtomic writes data to a file atomically using temp file + sync + rename
// Uses os.CreateTemp to avoid collision issues with concurrent writes
func (f *OSFileSystem) WriteFileAtomic(name string, data []byte, perm fs.FileMode) error {
	// Create temp file in the same directory as the target file
	// This ensures rename will be atomic (same filesystem)
	dir := filepath.Dir(name)

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()

	// Ensure cleanup on error
	defer func() {
		if tmpFile != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpName)
		}
	}()

	// Write data
	if _, err := tmpFile.Write(data); err != nil {
		return err
	}

	// Sync to ensure data is written to disk
	if err := tmpFile.Sync(); err != nil {
		return err
	}

	// Close the file
	if err := tmpFile.Close(); err != nil {
		return err
	}
	tmpFile = nil // Prevent deferred cleanup

	// Set proper permissions (CreateTemp creates with 0600)
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	// Atomically rename temp file to final name
	if err := os.Rename(tmpName, name); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	return nil
}

// IsNotExist returns true if the error indicates a file doesn't exist
func (f *OSFileSystem) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}
