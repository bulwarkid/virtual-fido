//go:build linux

package uhid

const (
	uhidEventStart     = 2
	uhidEventStop      = 3
	uhidEventOpen      = 4
	uhidEventClose     = 5
	uhidEventGetReport = 9
	uhidEventSetReport = 13
)
