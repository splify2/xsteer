package wire

import "testing"

// Разбор принятых байт не паникует и не отдаёт ничего за пределами входа.
func FuzzReasm(f *testing.F) {
	f.Add([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, uint32(1), uint32(0))
	f.Add(make([]byte, 100), uint32(7), uint32(3))
	f.Fuzz(func(t *testing.T, payload []byte, seq, isn uint32) {
		var r Reasm
		r.FeedAll(seq, isn, payload, func(body, hdr []byte, rel uint32) {})
		r.FeedAll(seq+uint32(len(payload)), isn, payload, func(body, hdr []byte, rel uint32) {})
	})
}

func FuzzBatchIter(f *testing.F) {
	buf := make([]byte, 64)
	n := BatchBuild(buf, [][]byte{{1, 2, 3}, {4}})
	f.Add(buf[:n])
	f.Fuzz(func(t *testing.T, pt []byte) {
		calls := 0
		ok := BatchIter(pt, func(fr []byte) { calls++ })
		if !ok && calls != 0 {
			t.Fatalf("битая пачка отдала %d кадров", calls)
		}
		if calls > BatchFramesMax {
			t.Fatalf("кадров %d больше предела", calls)
		}
	})
}

func FuzzRecParse(f *testing.F) {
	f.Add([]byte{0x17, 0x03, 0x03, 0x00, 0x10})
	f.Fuzz(func(t *testing.T, seg []byte) {
		if b, err := RecParse(seg); err == nil && len(b) != len(seg)-RecHdr {
			t.Fatalf("длина тела %d при сегменте %d", len(b), len(seg))
		}
	})
}
