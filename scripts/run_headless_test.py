#!/usr/bin/env python3
import os
import subprocess
import shutil
import sys
import time
import signal

def run_command(args, capture_output=False, shell=False, check=True):
    print(f"Running: {' '.join(args) if isinstance(args, list) else args}")
    return subprocess.run(args, capture_output=capture_output, shell=shell, check=check, text=True)

def run_sudo_command(args, password):
    if not password:
        print("Warning: SUDO_PASSWORD not set. Sudo commands may fail.")
    
    # Use -S to read from stdin
    full_cmd = ["sudo", "-S"] + args
    print(f"Running sudo: {' '.join(args)}")
    
    process = subprocess.Popen(full_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate(input=f"{password}\n")
    
    if process.returncode != 0:
        print(f"Sudo command failed with code {process.returncode}")
        print(f"Stderr: {stderr}")
    return process.returncode

def cleanup(sudo_password):
    print("Cleaning up...")
    run_sudo_command(["killall", "virtual-fido-macos"], sudo_password)
    try:
        run_command(["killall", "USBDriverInstaller"], check=False)
    except Exception:
        pass

def deploy():
    print("Deploying to /Applications...")
    app_path = "/Applications/USBDriverInstaller.app"
    if os.path.exists(app_path):
        shutil.rmtree(app_path)
    shutil.copytree("USBDriverInstaller.app", app_path)

def run_with_auth(cmd):
    print(f"Executing with auth handler: {' '.join(cmd)}")
    # Start auth handler in background
    auth_proc = subprocess.Popen(["osascript", "handle_auth.scpt"])
    
    try:
        # Run the installer command
        run_command(cmd)
    finally:
        # Kill the auth handler
        print("Stopping auth handler...")
        auth_proc.terminate()
        try:
            auth_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            auth_proc.kill()

def main():
    sudo_password = os.environ.get("SUDO_PASSWORD", "")
    
    try:
        cleanup(sudo_password)
        
        deploy()
        
        print("Uninstalling Driver...")
        try:
            run_with_auth(["/Applications/USBDriverInstaller.app/Contents/MacOS/USBDriverInstaller", "--uninstall"])
        except Exception as e:
            print(f"Uninstall failed (expected if not installed): {e}")

        print("Installing Driver...")
        run_with_auth(["/Applications/USBDriverInstaller.app/Contents/MacOS/USBDriverInstaller", "--install"])
        
        print("Running E2E Test...")
        run_command([sys.executable, "-u", "e2e_orch.py"])
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
