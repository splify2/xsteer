package tun

import (
	"net/netip"
	"strings"
)

// endpointCovered — накрывает ли хоть один из маршрутов AllowedIPs адрес какой-либо конечной
// точки (адреса хаба). Если да, то без отдельного обхода собственный трафик клиента к хабу уйдёт
// в туннель — а туннель в этот момент ещё не поднят, и это видно как «dial tcp …: i/o timeout».
//
// Здесь оно НЕ под тегом windows и не трогает системных вызовов нарочно: это чистая арифметика над
// префиксами, её проверяет стенд на любой системе, а решение о закреплении /32 к endpoint (как в
// WireGuard) слишком дорого ошибиться, чтобы оставлять его без проверки.
func endpointCovered(cidrs, endpoints []string) bool {
	var addrs []netip.Addr
	for _, ep := range endpoints {
		if a, err := netip.ParseAddr(strings.TrimSpace(ep)); err == nil {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return false
	}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// splitDefault отделяет маршрут по умолчанию IPv4 от остальных префиксов. Он ставится не вместе
// с остальными, а отдельно и позже — после доказательства, что туннель несёт трафик (см.
// routeGuard): иначе весь исходящий трафик машины уходит в туннель, который ничего не несёт.
func splitDefault(cidrs []string) (rest []string, full bool) {
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil && p.Bits() == 0 && p.Addr().Is4() {
			full = true
			continue
		}
		rest = append(rest, c)
	}
	return rest, full
}

// parseRouteGet достаёт шлюз и интерфейс из вывода `ip route get <адрес>`:
// «1.2.3.4 via 10.0.0.1 dev eth0 src ...» или «1.2.3.4 dev eth0 src ...» (подсеть без шлюза).
func parseRouteGet(out string) (via, dev string) {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			via = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	return via, dev
}
