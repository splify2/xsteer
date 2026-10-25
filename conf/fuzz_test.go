package conf

import "testing"

// Разбор файла и ссылки не паникует на любом входе.
func FuzzParse(f *testing.F) {
	f.Add([]byte("[Interface]\nPrivateKey = x\n"))
	f.Add([]byte("[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:443\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		Parse(b, RoleSpoke)
		Parse(b, RoleHub)
	})
}

func FuzzParseLink(f *testing.F) {
	f.Add("xs://k@1.2.3.4:443?sni=a.b#n")
	f.Fuzz(func(t *testing.T, s string) {
		ParseLink(s, RoleSpoke)
		ParseLink(s, RoleHub)
	})
}
