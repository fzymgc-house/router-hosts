// Package atomicfile is the shared write-and-rename helper used by server
// output generators and by client-side artifact writes (TMPL-04, D-12).
package atomicfile

import "github.com/samber/oops"

// Write writes content to path via create-temp/write/fsync/close/rename, so
// a concurrent reader never observes a partial file.
func Write(path string, content []byte) error {
	return oops.Errorf("not implemented")
}
