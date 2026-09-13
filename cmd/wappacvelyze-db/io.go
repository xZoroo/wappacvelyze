package main

import (
	"hash"
	"io"
)

// io2 writes to a file while hashing the same bytes, so the manifest checksum matches
// exactly what was written.
type io2 struct {
	file   io.Writer
	digest hash.Hash
}

func (w io2) Write(p []byte) (int, error) {
	w.digest.Write(p)
	return w.file.Write(p)
}
