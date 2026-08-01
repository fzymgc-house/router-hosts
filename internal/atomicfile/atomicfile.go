// Package atomicfile is the shared write-and-rename helper used by server
// output generators and by client-side artifact writes (TMPL-04, D-12).
package atomicfile

import (
	"os"
	"path/filepath"

	"github.com/samber/oops"
)

// Write writes content to path via create-temp/write/fsync/close/rename, so
// a concurrent reader never observes a partial file. The temp file is
// created in filepath.Dir(path) so the rename stays atomic (same
// filesystem).
func Write(path string, content []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.*")
	if err != nil {
		return oops.Wrapf(err, "create temp file")
	}
	tmpPath := f.Name()

	_, writeErr := f.Write(content)
	if writeErr != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return oops.Wrapf(writeErr, "write file")
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "fsync file")
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "close file")
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return oops.Wrapf(err, "rename file")
	}

	return nil
}
