//go:build windows

// Package usbipwin2 provides a Windows usbip-win2 client wrapper.
package usbipwin2

import (
	"errors"
	"fmt"
	"net"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// guidVHCI is the driver device interface GUID (vhci.h GUID_DEVINTERFACE_USB_HOST_CONTROLLER).
var guidVHCI = windows.GUID{
	Data1: 0xB4030C06,
	Data2: 0xDC5F,
	Data3: 0x4FCC,
	Data4: [8]byte{0x87, 0xEB, 0xE5, 0x51, 0x5A, 0x09, 0x35, 0xC0},
}

// Sizes and IOCTL constants from usbip-win2 headers.
const (
	busIDSize       = 32
	serviceSize     = 32
	hostSize        = 1025
	fileDevUnknown  = 0x22
	methodBuffered  = 0
	fileReadAccess  = 0x1
	fileWriteAccess = 0x2
)

// IOCTLs (vhci.h).
var (
	ioctlPluginHardware = ctlCode(
		fileDevUnknown,
		0x800,
		methodBuffered,
		fileReadAccess|fileWriteAccess,
	)
	ioctlPlugoutHardware = ctlCode(
		fileDevUnknown,
		0x801,
		methodBuffered,
		fileReadAccess|fileWriteAccess,
	)
	ioctlGetImportedDevs = ctlCode(
		fileDevUnknown,
		0x802,
		methodBuffered,
		fileReadAccess|fileWriteAccess,
	)
	ioctlSetPersistent = ctlCode(
		fileDevUnknown,
		0x803,
		methodBuffered,
		fileReadAccess|fileWriteAccess,
	)
	ioctlGetPersistent = ctlCode(
		fileDevUnknown,
		0x804,
		methodBuffered,
		fileReadAccess|fileWriteAccess,
	)
)

// ctlCode builds a Windows CTL_CODE.
func ctlCode(devType, function, method, access uint32) uint32 {
	return (devType << 16) | (access << 14) | (function << 2) | method
}

// base mirrors usbip::vhci::base.
type base struct {
	Size uint32
}

// importedDeviceLocation mirrors usbip::vhci::imported_device_location.
type importedDeviceLocation struct {
	Port    int32
	BusID   [busIDSize]byte
	Service [serviceSize]byte
	Host    [hostSize]byte
}

// pluginHardware mirrors usbip::vhci::ioctl::plugin_hardware.
type pluginHardware struct {
	base
	importedDeviceLocation
}

// plugoutHardware mirrors usbip::vhci::ioctl::plugout_hardware.
type plugoutHardware struct {
	base
	Port int32
}

// Client is a Windows usbip-win2 client wrapper. Requires the usbip-win2 driver.
type Client struct {
	Address string // host:port of usbip server
	busid   string // busid exported by server (optional if only one device)
}

// New constructs a client for the given address.
func New(address string) *Client {
	return &Client{Address: address}
}

// SetBusID sets the remote busid to import (when multiple exports exist).
func (c *Client) SetBusID(busid string) {
	c.busid = busid
}

// Attach connects to the driver and issues PLUGIN_HARDWARE to import the device.
func (c *Client) Attach() (int, error) {
	if c.Address == "" {
		return 0, errors.New("usbipwin2: address required")
	}
	host, port, err := splitHostPort(c.Address)
	if err != nil {
		return 0, err
	}
	path, err := firstDevicePath(guidVHCI)
	if err != nil {
		return 0, fmt.Errorf("usbipwin2: open vhci: %w", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("usbipwin2: utf16 path: %w", err)
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("usbipwin2: createfile: %w", err)
	}
	defer windows.CloseHandle(h)

	req := pluginHardware{
		base: base{Size: uint32(unsafe.Sizeof(pluginHardware{}))},
	}
	if err := fillString(req.BusID[:], c.busid); err != nil {
		return 0, err
	}
	if err := fillString(req.Service[:], port); err != nil {
		return 0, err
	}
	if err := fillString(req.Host[:], host); err != nil {
		return 0, err
	}

	out := req
	var bytesRet uint32
	err = windows.DeviceIoControl(
		h,
		ioctlPluginHardware,
		(*byte)(unsafe.Pointer(&req)),
		uint32(unsafe.Sizeof(req)),
		(*byte)(unsafe.Pointer(&out)),
		uint32(unsafe.Sizeof(out)),
		&bytesRet,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("usbipwin2: ioctl plugin: %w", err)
	}
	expected := uint32(unsafe.Offsetof(out.Port)) + 4
	if bytesRet < expected || out.Port <= 0 {
		return 0, fmt.Errorf(
			"usbipwin2: plugin returned invalid port (%d, %d bytes)",
			out.Port,
			bytesRet,
		)
	}
	return int(out.Port), nil
}

// Detach detaches a specific port (>0) or all ports (<=0).
func (c *Client) Detach(port int) error {
	path, err := firstDevicePath(guidVHCI)
	if err != nil {
		return fmt.Errorf("usbipwin2: open vhci: %w", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("usbipwin2: utf16 path: %w", err)
	}
	h, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("usbipwin2: createfile: %w", err)
	}
	defer windows.CloseHandle(h)

	req := plugoutHardware{
		base: base{Size: uint32(unsafe.Sizeof(plugoutHardware{}))},
		Port: int32(port),
	}
	var bytesRet uint32
	err = windows.DeviceIoControl(
		h,
		ioctlPlugoutHardware,
		(*byte)(unsafe.Pointer(&req)),
		uint32(unsafe.Sizeof(req)),
		nil,
		0,
		&bytesRet,
		nil,
	)
	if err != nil {
		return fmt.Errorf("usbipwin2: ioctl plugout: %w", err)
	}
	return nil
}

// fillString copies a UTF-8 string into a fixed-size C buffer.
func fillString(dst []byte, s string) error {
	if s == "" {
		return nil
	}
	if !utf8.ValidString(s) {
		return errors.New("usbipwin2: string not utf8")
	}
	if len(s) >= len(dst) {
		return fmt.Errorf("usbipwin2: string too long (max %d)", len(dst)-1)
	}
	copy(dst, []byte(s))
	dst[len(s)] = 0
	return nil
}

// splitHostPort splits a host:port address.
func splitHostPort(addr string) (host, port string, err error) {
	return net.SplitHostPort(addr)
}

// firstDevicePath returns the first present device interface path for the GUID.
func firstDevicePath(classGUID windows.GUID) (string, error) {
	devs, err := setupDiGetClassDevs(
		&classGUID,
		0,
		0,
		digcfPresent|digcfDeviceInterface,
	)
	if err != nil {
		return "", err
	}
	defer setupDiDestroyDeviceInfoList(devs)

	var data spDeviceInterfaceData
	data.cbSize = uint32(unsafe.Sizeof(data))
	if err = setupDiEnumDeviceInterfaces(devs, 0, &classGUID, 0, &data); err != nil {
		return "", err
	}

	// Get required size.
	var required uint32
	err = setupDiGetDeviceInterfaceDetail(devs, &data, nil, 0, &required, 0)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", err
	}
	buf := make([]byte, required)
	detail := (*spDeviceInterfaceDetailData)(unsafe.Pointer(&buf[0]))
	detail.cbSize = uint32(unsafe.Sizeof(spDeviceInterfaceDetailData{}))
	if err = setupDiGetDeviceInterfaceDetail(
		devs,
		&data,
		detail,
		required,
		nil,
		0,
	); err != nil {
		return "", err
	}
	path := windows.UTF16PtrToString(&detail.devicePath[0])
	if path == "" {
		return "", errors.New("usbipwin2: empty device path")
	}
	return path, nil
}

// SetupAPI bindings.
var (
	modsetupapi                          = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetClassDevsW             = modsetupapi.NewProc("SetupDiGetClassDevsW")
	procSetupDiEnumDeviceInterfaces      = modsetupapi.NewProc("SetupDiEnumDeviceInterfaces")
	procSetupDiGetDeviceInterfaceDetailW = modsetupapi.NewProc("SetupDiGetDeviceInterfaceDetailW")
	procSetupDiDestroyDeviceInfoList     = modsetupapi.NewProc("SetupDiDestroyDeviceInfoList")
)

// SetupAPI flags for SetupDiGetClassDevs.
const (
	digcfPresent         = 0x00000002
	digcfDeviceInterface = 0x00000010
)

// spDeviceInterfaceData mirrors SP_DEVICE_INTERFACE_DATA.
type spDeviceInterfaceData struct {
	cbSize    uint32
	ClassGuid windows.GUID
	Flags     uint32
	reserved  uintptr
}

// spDeviceInterfaceDetailData mirrors SP_DEVICE_INTERFACE_DETAIL_DATA_W.
type spDeviceInterfaceDetailData struct {
	cbSize     uint32
	devicePath [1]uint16
}

// setupDiGetClassDevs wraps SetupDiGetClassDevsW.
func setupDiGetClassDevs(
	classGUID *windows.GUID,
	enumerator uintptr,
	hwndParent uintptr,
	flags uint32,
) (windows.Handle, error) {
	r0, _, e1 := procSetupDiGetClassDevsW.Call(
		uintptr(unsafe.Pointer(classGUID)),
		enumerator,
		hwndParent,
		uintptr(flags),
	)
	handle := windows.Handle(r0)
	if handle == windows.InvalidHandle {
		if e1 != nil {
			return handle, e1
		}
		return handle, windows.ERROR_INVALID_PARAMETER
	}
	return handle, nil
}

// setupDiEnumDeviceInterfaces wraps SetupDiEnumDeviceInterfaces.
func setupDiEnumDeviceInterfaces(
	devinfo windows.Handle,
	devinfoData uintptr,
	classGUID *windows.GUID,
	index uint32,
	data *spDeviceInterfaceData,
) error {
	r1, _, e1 := procSetupDiEnumDeviceInterfaces.Call(
		uintptr(devinfo),
		devinfoData,
		uintptr(unsafe.Pointer(classGUID)),
		uintptr(index),
		uintptr(unsafe.Pointer(data)),
	)
	if r1 == 0 {
		if e1 != nil {
			return e1
		}
		return windows.ERROR_INVALID_PARAMETER
	}
	return nil
}

// setupDiGetDeviceInterfaceDetail wraps SetupDiGetDeviceInterfaceDetailW.
func setupDiGetDeviceInterfaceDetail(
	devinfo windows.Handle,
	data *spDeviceInterfaceData,
	detail *spDeviceInterfaceDetailData,
	detailSize uint32,
	requiredSize *uint32,
	devinfoData uintptr,
) error {
	r1, _, e1 := procSetupDiGetDeviceInterfaceDetailW.Call(
		uintptr(devinfo),
		uintptr(unsafe.Pointer(data)),
		uintptr(unsafe.Pointer(detail)),
		uintptr(detailSize),
		uintptr(unsafe.Pointer(requiredSize)),
		devinfoData,
	)
	if r1 == 0 {
		if e1 != nil {
			return e1
		}
		return windows.ERROR_INVALID_PARAMETER
	}
	return nil
}

// setupDiDestroyDeviceInfoList wraps SetupDiDestroyDeviceInfoList.
func setupDiDestroyDeviceInfoList(devinfo windows.Handle) error {
	r1, _, e1 := procSetupDiDestroyDeviceInfoList.Call(uintptr(devinfo))
	if r1 == 0 {
		if e1 != nil {
			return e1
		}
		return windows.ERROR_INVALID_PARAMETER
	}
	return nil
}
