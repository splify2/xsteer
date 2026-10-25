package link

import "testing"

func FuzzParseSeg(f *testing.F) {
	f.Add(make([]byte, 40))
	f.Fuzz(func(t *testing.T, pkt []byte) { ParseSeg(pkt) })
}
