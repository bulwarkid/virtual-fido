import subprocess
import os
import signal
import sys
import time
import threading
import argparse

# Comprehensive E2E Test Suite for Virtual FIDO on macOS VM
# Supports Online/Offline, Auto/Semi-Auto, and Cold Start scenarios.

def read_stream(stream, prefix):
    for line in iter(stream.readline, ''):
        print(f"{prefix}{line.strip()}")
        sys.stdout.flush()
    stream.close()

class E2ETestSuite:
    def __init__(self, binary, mode="offline", semi_auto=False):
        self.binary = binary
        self.mode = mode
        self.semi_auto = semi_auto
        self.vf_proc = None
        self.server_proc = None
        self.binary_name = os.path.basename(binary)
        
    def cleanup(self):
        print(f"Cleanup: Killing existing {self.binary_name} and test server...")
        subprocess.run(["sudo", "killall", self.binary_name], stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "test/server.py"], stderr=subprocess.DEVNULL)
        time.sleep(2)

    def start_local_server(self):
        if self.mode == "offline":
            print("Starting local WebAuthn test server...")
            self.server_proc = subprocess.Popen(
                [sys.executable, "test/server.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            # Give it a moment to start
            time.sleep(2)

    def run_test_cycle(self, name):
        print(f"\n>>> Starting Test Cycle: {name} ({self.mode}, semi_auto={self.semi_auto})")
        
        seed_path = "/tmp/seed_e2e"
        if not os.path.exists(seed_path):
            with open(seed_path, "w") as f:
                f.write("af"*32)

        # 1. Start Virtual FIDO in deferred mode
        cmd = [
            "sudo", self.binary, "run",
            "--device-name", "HH-E2E",
            "--seed-file", seed_path,
            "--deferred-start"
        ]
        if not self.semi_auto:
            cmd.append("--always-approve")
        
        self.vf_proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        vhid_thread = threading.Thread(target=read_stream, args=(self.vf_proc.stdout, f"[{self.binary_name}] "), daemon=True)
        vhid_thread.start()

        def vhid_monitor():
            # In a real setup, we'd need to thread-safely read vf_proc.stdout.
            # Since read_stream is already printing it, we might need a shared queue.
            # For simplicity, let's just use the current semi-auto logic but fix the trigger.
            pass

        # 2. Insert Device
        print("COMMAND: insert")
        self.vf_proc.stdin.write("insert\n")
        self.vf_proc.stdin.flush()
        time.sleep(5) 

        # 3. Run Playwright
        if self.mode == "offline":
            site = "http://localhost:8000"
        elif self.mode == "online":
            site = "https://webauthn.io"
        else:
            site = getattr(self, "custom_site", "https://webauthn.io")
            
        pw_cmd = [
            sys.executable, "test/playwright_fido.py",
            "--username", f"e2e_{int(time.time())}",
            "--site", site
        ]
        
        print(f"Launching Playwright against {site}...")
        pw_proc = subprocess.Popen(
            pw_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Monitor both for semi-auto
        for line in iter(pw_proc.stdout.readline, ''):
            print(f"PLAYWRIGHT: {line.strip()}")
            # If we see the PW waiting, and we are in semi-auto, send touch after a delay
            if self.semi_auto and "Waiting for FIDO" in line:
                print("Detected FIDO wait in Playwright. Sending 'touch' in 2s...")
                time.sleep(2)
                self.vf_proc.stdin.write("touch\n")
                self.vf_proc.stdin.flush()
        
        pw_proc.wait()
        success = pw_proc.returncode == 0
        
        # 4. Remove Device
        print("COMMAND: remove")
        self.vf_proc.stdin.write("remove\n")
        self.vf_proc.stdin.flush()
        time.sleep(2)

        # 5. Shutdown Service
        self.vf_proc.terminate()
        self.vf_proc.wait()
        
        return success

    def run_all(self):
        self.cleanup()
        
        results = {}
        
        if self.mode == "offline":
            self.start_local_server()
            print("\n--- SCENARIO: Automated Offline Flow ---")
            results["Auto-Offline-Flow"] = self.run_test_cycle("Auto-Offline")
        elif self.mode == "online":
            print("\n--- SCENARIO: Automated WebAuthn.io Flow ---")
            results["Auto-WebAuthn-IO"] = self.run_test_cycle("Auto-WebAuthn-IO")
        elif self.mode == "custom":
            print(f"\n--- SCENARIO: Automated Custom Flow ({self.custom_site}) ---")
            results["Auto-Custom-Flow"] = self.run_test_cycle_for_site("Auto-Custom", self.custom_site)
        else:
            # Fallback/Default: Run all if mode is something else or not set (though __init__ sets it)
            self.start_local_server()
            results["Auto-Offline-Flow"] = self.run_test_cycle("Auto-Offline")
            self.mode = "online"
            results["Auto-WebAuthn-IO"] = self.run_test_cycle("Auto-WebAuthn-IO")
            results["Auto-Yubico-Flow"] = self.run_test_cycle_for_site("Auto-Yubico", "https://demo.yubico.com/webauthn")
        
        print("\n" + "="*30)
        print("E2E SUITE RESULTS")
        print("="*30)
        for test, res in results.items():
            status = "PASS" if res else "FAIL"
            print(f"{test}: {status}")
        
        if self.server_proc:
            self.server_proc.terminate()
            
        return all(results.values())

    def run_test_cycle_for_site(self, name, site):
        # Helper to run a cycle for a specific URL
        # We can temporarily override self.mode or just call run_test_cycle with logic
        original_mode = self.mode
        self.mode = "custom"
        self.custom_site = site
        success = self.run_test_cycle(name)
        self.mode = original_mode
        return success

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="./virtual-fido-vhid")
    parser.add_argument("--mode", choices=["online", "offline", "custom"], default="offline")
    parser.add_argument("--custom-site", help="Custom site URL for 'custom' mode")
    parser.add_argument("--semi-auto", action="store_true")
    args = parser.parse_args()
    
    suite = E2ETestSuite(args.binary, mode=args.mode, semi_auto=args.semi_auto)
    if args.custom_site:
        suite.custom_site = args.custom_site
        
    if suite.run_all():
        sys.exit(0)
    else:
        sys.exit(1)
