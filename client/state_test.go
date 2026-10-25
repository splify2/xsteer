package client

// Снимок состояния при уходе: ноль пишется в СНИМОК, а не в счётчик живых соединений.
//
// ЗАЧЕМ. stateLoop при отмене контекста делал `c.stats.up.Store(0)` и писал последний снимок,
// чтобы файл не остался врать «up». Но up — не флаг, а число живых соединений, и сессии
// уменьшают его своими defer независимо: обнуление под ними уводит счётчик в минус, и второй
// читатель снимка (подкоманда status, графический клиент) увидел бы «conns: -3». Сегодня
// читатель один и после ухода снимков не делает — поэтому это не наблюдалось. Стенд проверяет
// то, что и должно быть верно по смыслу: после ухода файл говорит «не поднят, соединений ноль», а
// счётчик, которым владеют сессии, остаётся их.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/splify2/xsteer/noise"
)

func TestУходПишетНольВСнимокНеВСчётчик(t *testing.T) {
	dir := t.TempDir()
	c := &Client{opt: Options{StatePath: filepath.Join(dir, "state.json")}}
	c.stats.up.Store(2) // две живые сессии, каждая сама сделает Add(-1) при выходе
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.stateLoop(ctx, "xstest0")

	if got := c.stats.up.Load(); got != 2 {
		t.Fatalf("счётчик живых соединений после ухода %d, ждали 2 — он принадлежит сессиям", got)
	}
	b, err := os.ReadFile(c.opt.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Up || st.Conns != 0 {
		t.Fatalf("последний снимок при уходе: up=%v conns=%d, ждали false/0", st.Up, st.Conns)
	}
}

// Хаб без FlagSplit (прежняя версия): пачка стоит на одном кадре; с битом — прежнее начало (2).
func TestХабБезFlagSplitНеПачкуется(t *testing.T) {
	s := &sess{}
	s.batchMax.Store(2)
	s.applyPeerSplit(noise.Payload{Ver: noise.ProtoVer, Flags: 1})
	if s.peerSplit || s.batchMax.Load() != 1 {
		t.Fatalf("старый хаб: peerSplit=%v batchMax=%d", s.peerSplit, s.batchMax.Load())
	}
	s2 := &sess{}
	s2.batchMax.Store(2)
	s2.applyPeerSplit(noise.Payload{Ver: noise.ProtoVer, Flags: noise.FlagSplit})
	if !s2.peerSplit || s2.batchMax.Load() != 2 {
		t.Fatalf("новый хаб: peerSplit=%v batchMax=%d", s2.peerSplit, s2.batchMax.Load())
	}
}
