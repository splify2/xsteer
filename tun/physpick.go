package tun

// defRoute — маршрут по умолчанию из таблицы системы: индекс интерфейса и СМЕЩЕНИЕ метрики
// самого маршрута (у Windows MIB_IPFORWARD_ROW2.Metric — не действующая метрика).
type defRoute struct {
	Index  uint32
	Offset uint32
}

// pickDefault выбирает маршрут по умолчанию, которым система реально ходит наружу: действующая
// метрика — сумма метрики интерфейса и смещения маршрута. Две подключённые сети (кабель и Wi-Fi)
// обычно различаются именно метрикой интерфейса, а смещение у обоих нулевое; сравнение одних
// смещений выбирало интерфейс по порядку строк в таблице — и сокет хаба привязывался к каналу,
// которым система наружу не ходит. Интерфейс без известной метрики считается худшим.
//
// При равной сумме побеждает меньший индекс (выбор детерминирован, а не зависит от порядка
// таблицы), и tie говорит вызывающему назвать неоднозначность в журнале.
func pickDefault(routes []defRoute, ifMetric map[uint32]uint32) (best defRoute, ok, tie bool) {
	const unknown = ^uint64(0) >> 1
	eff := func(r defRoute) uint64 {
		m, known := ifMetric[r.Index]
		if !known {
			return unknown
		}
		return uint64(m) + uint64(r.Offset)
	}
	for _, r := range routes {
		switch {
		case !ok || eff(r) < eff(best):
			best, ok, tie = r, true, false
		case eff(r) == eff(best) && r.Index != best.Index:
			tie = true
			if r.Index < best.Index {
				best = r
			}
		}
	}
	return best, ok, tie
}
