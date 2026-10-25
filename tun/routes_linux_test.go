//go:build linux

package tun

import (
	"errors"
	"net/netip"
	"testing"
)

// Обход к хабу не встал при полном туннеле: «полного туннеля» нет, иначе сторож поставил бы
// маршрут по умолчанию, и хаб ушёл бы в собственный туннель.
func TestSetupRoutesОбходНеВсталНетПолногоТуннеля(t *testing.T) {
	old := addBypassFn
	defer func() { addBypassFn = old }()
	addBypassFn = func(string, netip.Addr) error { return errors.New("нет маршрута") }
	full, err := SetupRoutes("xs-test0", []string{"0.0.0.0/0"}, []string{"203.0.113.5"})
	if err == nil {
		t.Fatal("ошибка обхода проглочена")
	}
	if full {
		t.Fatal("при неставшем обходе полный туннель объявлен")
	}
}
