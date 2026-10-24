package tun

import "testing"

// Кабель и Wi-Fi: смещения нулевые у обоих, различает метрика интерфейса. Выбор не должен
// зависеть от порядка строк (I-120).
func TestPickDefaultСуммаМетрикиИнтерфейса(t *testing.T) {
	ifm := map[uint32]uint32{3: 25, 7: 50} // 3 — кабель, 7 — Wi-Fi
	wifi, cable := defRoute{Index: 7}, defRoute{Index: 3}
	for _, rows := range [][]defRoute{{wifi, cable}, {cable, wifi}} {
		b, ok, tie := pickDefault(rows, ifm)
		if !ok || b.Index != 3 || tie {
			t.Fatalf("%v: выбран %d (ok=%v tie=%v), ждали кабель 3", rows, b.Index, ok, tie)
		}
	}
	// Смещение маршрута тоже считается: 25+100 хуже 50+0.
	b, _, _ := pickDefault([]defRoute{{Index: 3, Offset: 100}, {Index: 7}}, ifm)
	if b.Index != 7 {
		t.Fatalf("выбран %d, ждали 7 (сумма 50 против 125)", b.Index)
	}
}

func TestPickDefaultРавенствоОпределённоИНазвано(t *testing.T) {
	ifm := map[uint32]uint32{5: 10, 2: 10}
	for _, rows := range [][]defRoute{{{Index: 5}, {Index: 2}}, {{Index: 2}, {Index: 5}}} {
		b, ok, tie := pickDefault(rows, ifm)
		if !ok || !tie || b.Index != 2 {
			t.Fatalf("%v: index=%d ok=%v tie=%v, ждали 2 и tie", rows, b.Index, ok, tie)
		}
	}
	if _, ok, _ := pickDefault(nil, ifm); ok {
		t.Fatal("пустая таблица не даёт выбора")
	}
	// Интерфейс без метрики — худший.
	if b, _, _ := pickDefault([]defRoute{{Index: 9}, {Index: 5}}, ifm); b.Index != 5 {
		t.Fatalf("выбран %d, ждали 5", b.Index)
	}
}
