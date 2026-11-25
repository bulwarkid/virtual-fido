package fido_client

import "github.com/bulwarkid/virtual-fido/ctap"

// The default client shows a dedicated prompt for touch-to-select requests.
var _ ctap.DeviceSelectionApprover = DefaultFIDOClient{}
