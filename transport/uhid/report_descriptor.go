package uhid

// ReportDescriptorFIDO is a standard 64-byte in/out HID report descriptor for FIDO.
var ReportDescriptorFIDO = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, // Usage (U2F Authenticator device)
	0xA1, 0x01, // Collection (Application)
	0x09, 0x20, // Usage (Input Report Data)
	0x15, 0x00, // Logical Minimum (0)
	0x26, 0xFF, 0x00, // Logical Maximum (255)
	0x75, 0x08, // Report Size (8)
	0x95, 0x40, // Report Count (64)
	0x81, 0x02, // Input (Data, Var, Abs)
	0x09, 0x21, // Usage (Output Report Data)
	0x15, 0x00, // Logical Minimum (0)
	0x26, 0xFF, 0x00, // Logical Maximum (255)
	0x75, 0x08, // Report Size (8)
	0x95, 0x40, // Report Count (64)
	0x91, 0x02, // Output (Data, Var, Abs)
	0xC0, // End Collection
}
