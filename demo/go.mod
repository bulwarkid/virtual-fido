module demo

go 1.18

replace virtual_fido => ./../virtual_fido

require virtual_fido v0.0.0-00010101000000-000000000000

require (
	github.com/fxamacker/cbor/v2 v2.4.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20220829220503-c86fa9a7ed90 // indirect
)
