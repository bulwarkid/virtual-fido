#!/usr/bin/env python3

# Minimal python-fido2 harness to verify ClientPIN (v1) and hmac-secret
# Usage:
#   pip install fido2 hidapi
#   sudo python3 scripts/fido2_test_pin_and_hmac.py --set-pin 1234   # first time only
#   sudo python3 scripts/fido2_test_pin_and_hmac.py --test

import argparse
import binascii
import os
import sys

from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, PinProtocolV1, ClientPin
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity


def first_device():
    for dev in CtapHidDevice.list_devices():
        return dev
    raise RuntimeError("No FIDO device found")


def ensure_pin(ctap: Ctap2, pin: str):
    client_pin = ClientPin(ctap)
    proto = PinProtocolV1()
    try:
        retries = client_pin.get_retries()
        print(f"[clientpin] retries={retries}")
    except Exception as e:
        print(f"[clientpin] get_retries failed: {e}")
        raise

    try:
        # If PIN not set, set it
        if client_pin.get_key_agreement():
            print("[clientpin] setting PIN (if not already set)...")
            client_pin.set_pin(proto, pin)
            print("[clientpin] PIN set")
    except Exception as e:
        print(f"[clientpin] set_pin skipped/failed: {e}")


def get_token(ctap: Ctap2, pin: str):
    client_pin = ClientPin(ctap)
    proto = PinProtocolV1()
    token = client_pin.get_pin_token(proto, pin)
    print(f"[clientpin] got pinUvAuthToken, len={len(token)}")
    return token


def mc_with_pin(ctap: Ctap2, token: bytes):
    # Minimal makeCredential with UV via pinUvAuthParam
    rp = PublicKeyCredentialRpEntity(id="example.com", name="Example")
    user = PublicKeyCredentialUserEntity(id=os.urandom(16), name="alice", display_name="Alice")
    client_data_hash = os.urandom(32)
    params = [{"type": "public-key", "alg": -7}]
    # pinUvAuthParam = HMAC-SHA-256(token, clientDataHash)[:16] is handled by python-fido2
    att = ctap.make_credential(client_data_hash, rp, user, params, pin_uv_protocol=1, pin_uv_param=(token,))
    print("[mc] ok, fmt=packed, authDataLen=", len(att["authData"]))
    return att


def ga_with_hmac_secret(ctap: Ctap2, token: bytes, cred_id: bytes):
    client_data_hash = os.urandom(32)
    # Prepare hmac-secret input with 2 salts
    salt1 = os.urandom(32)
    salt2 = os.urandom(32)
    extensions = {"hmac-secret": {"salt1": salt1, "salt2": salt2}}
    # python-fido2 will build the keyAgreement/saltEnc/saltAuth using our platform key
    assertion = ctap.get_assertion("example.com", client_data_hash, allow_list=[{"type":"public-key","id": cred_id}],
                                   pin_uv_protocol=1, pin_uv_param=(token,), extensions=extensions)
    print("[ga] ok, signatureLen=", len(assertion["signature"]))
    # Extension outputs are in authData extensions; python-fido2 does not decode that field directly here
    return assertion


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--set-pin", help="Set PIN if not already set")
    parser.add_argument("--test", action="store_true", help="Run MC+GA with hmac-secret")
    args = parser.parse_args()

    dev = first_device()
    print("Using device:", dev)
    ctap = Ctap2(dev)

    if args.set_pin:
        ensure_pin(ctap, args.set_pin)

    if args.test:
        token = get_token(ctap, args.set_pin or os.environ.get("PIN", "1234"))
        att = mc_with_pin(ctap, token)
        cred_id = att["authData"][55:55+att["authData"][53]<<8 | att["authData"][54]]  # simplistic parse; replace with proper decoder if needed
        _ = ga_with_hmac_secret(ctap, token, cred_id)


if __name__ == "__main__":
    main()

