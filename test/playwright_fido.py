import sys
import time
import argparse
from playwright.sync_api import sync_playwright

def screenshot(page, filename_prefix):
    """Helper function to take screenshots."""
    page.screenshot(path=f"videos/{filename_prefix}.png")

def run(args):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(record_video_dir="videos/")
        page = context.new_page()
        
        # Site-specific selectors and logic
        is_yubico = "yubico.com" in args.site
        is_webauthn_io = "webauthn.io" in args.site
        is_local = "localhost" in args.site

        try:
            print(f"Navigating to {args.site}...")
            page.goto(args.site)
            screenshot(page, "01_navigation")

            if is_yubico:
                # Yubico demo requires starting the demo first
                start_btn = page.locator('button:has-text("START THE WEBAUTHN DEMO")')
                if start_btn.is_visible():
                    start_btn.click()
                
                # Registration
                print(f"Registering user: {args.username}")
                page.fill("input#username", args.username)
                page.fill("input#pwd", "password123") # Yubico demo needs a password
                page.click('button:has-text("REGISTER")')
                screenshot(page, "02_registration_clicked")
            elif is_webauthn_io or is_local:
                # webauthn.io or local server
                user_input = "input#input-email" if is_webauthn_io else "input#username"
                reg_btn = "button#register-button" if is_webauthn_io else "button#register"
                
                print(f"Registering user: {args.username}")
                page.fill(user_input, args.username)
                page.click(reg_btn)
                screenshot(page, "02_registration_clicked")

            # Generic hotkey hack for the native prompt
            print("Sending hotkey hack (ArrowDown + Enter)...")
            for _ in range(3):
                time.sleep(1)
                page.keyboard.press("ArrowDown")
                time.sleep(0.5)
                page.keyboard.press("Enter")
            
            print("Waiting for FIDO registration prompt...")
            # Success markers
            if is_yubico:
                page.wait_for_selector("text=Success! You have registered", timeout=120000)
            else:
                page.wait_for_selector("text=Registration Successful", timeout=120000)
                
            print("Registration successful!")
            screenshot(page, "03_registration_success")

            time.sleep(2)
            
            # --- LOGIN FLOW ---
            if is_yubico:
                page.click('a:has-text("Sign in")')
                print(f"Logging in user: {args.username}")
                page.fill("input#username", args.username)
                page.fill("input#pwd", "password123")
                page.click('button:has-text("SIGN IN")')
                screenshot(page, "04_login_clicked")
            elif is_webauthn_io or is_local:
                login_btn = "button#login-button" if is_webauthn_io else "button#login"
                print(f"Logging in user: {args.username}")
                if is_webauthn_io:
                    page.fill("input#input-email", args.username)
                page.click(login_btn)
                screenshot(page, "04_login_clicked")

            print("Waiting for FIDO login prompt...")
            # Send hotkey hack again for login prompt
            for _ in range(3):
                time.sleep(1)
                page.keyboard.press("ArrowDown")
                time.sleep(0.5)
                page.keyboard.press("Enter")

            if is_yubico:
                page.wait_for_selector("text=You are signed in", timeout=120000)
            else:
                page.wait_for_selector("text=Login Successful", timeout=120000)
                
            print("Login successful!")
            screenshot(page, "05_login_success")

        except Exception as e:
            print(f"Test failed or timed out: {e}")
            screenshot(page, "03_registration_failed") # Or 05_login_failed depending on where it failed
            sys.exit(1)
        finally:
            time.sleep(2) # Give some time to see the final state
            context.close()
            browser.close()
            sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--site", default="https://webauthn.io")
    args = parser.parse_args()
    
    run(args)
