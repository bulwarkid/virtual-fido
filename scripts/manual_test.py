#!/usr/bin/env python3
"""
Comprehensive WebAuthn Test Script v2
Supports multiple sites and detailed logging for debugging Virtual FIDO.
"""
import sys
import time
import argparse
import os
from playwright.sync_api import sync_playwright

def run_tests(sites_string, username, headless=False):
    sites = sites_string.split(',')
    results = {}
    
    os.makedirs("videos", exist_ok=True)

    for site in sites:
        site = site.strip()
        if not site: continue
        
        print(f"\n{'='*60}")
        print(f"TESTING SITE: {site}")
        print(f"BROWSER: Chrome (System)")
        print(f"USER: {username}")
        print(f"{'='*60}\n")
        
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(
                    headless=headless,
                    channel="chrome",
                    args=["--enable-logging", "--v=1"]
                )
                context = browser.new_context(record_video_dir="videos/")
                page = context.new_page()
                
                # Enhanced console logging
                def handle_log(msg):
                    if "navigator.credentials" in msg.text:
                        print(f"🔥 WEBAUTHN_API: {msg.text}")
                    else:
                        print(f"LOG: {msg.text}")
                page.on("console", handle_log)

                # Site Identifiers
                is_yubico = "yubico.com" in site
                is_webauthn_io = "webauthn.io" in site
                is_passwordless_id = "passwordless.id" in site
                is_webauthn_me = "webauthn.me" in site
                is_passkeys_io = "passkeys.io" in site

                # [1] Navigation
                print(f"[1] Navigating to {site}...")
                page.goto(site, timeout=60000)
                prefix = site.replace('https://', '').replace('/', '_').replace('.', '_')
                page.screenshot(path=f"videos/{prefix}_01_nav.png")
                
                # [2] Site-Specific Interaction
                print(f"[2] Initiating registration flow...")
                if is_yubico:
                    page.click('button:has-text("NEXT")', timeout=30000)
                elif is_webauthn_io:
                    page.fill("input#input-email", username, timeout=30000)
                    page.click("button#register-button")
                elif is_passwordless_id:
                    page.fill("input#nickname", username, timeout=30000)
                    page.click('button:has-text("Register")', timeout=30000)
                elif is_webauthn_me:
                    page.click("button#register", timeout=30000)
                elif is_passkeys_io:
                    # Look for "Try demo" or "Create account"
                    if page.locator('text=Create account').is_visible():
                        page.click('text=Create account')
                    page.fill("input[type='email']", f"{username}@example.com", timeout=30000)
                    page.click("button[type='submit']")
                else:
                    print("Unknown site, trying generic 'register' click...")
                    page.click('button:has-text("Register")', timeout=5000)
                
                page.screenshot(path=f"videos/{prefix}_02_initiated.png")
                
                # [3] Handle Native Prompt (Hotkeys)
                print(f"[3] Waiting and sending hotkeys...")
                time.sleep(5) # Wait for prompt
                for _ in range(3):
                    page.keyboard.press("ArrowDown")
                    time.sleep(0.5)
                    page.keyboard.press("Enter")
                    time.sleep(1)
                
                page.screenshot(path=f"videos/{prefix}_03_after_hotkeys.png")

                # [4] Result Detection
                success_indicators = [
                    "Registration Successful",
                    "Registration completed",
                    "Success",
                    "Welcome",
                    "Successfully registered",
                    "Credential created"
                ]
                
                print(f"[4] Checking for success...")
                found = False
                for indicator in success_indicators:
                    try:
                        if page.locator(f"text={indicator}").is_visible(timeout=5000):
                            print(f"✅ PASSED: Found indicator '{indicator}'")
                            found = True
                            break
                    except:
                        continue
                
                if not found:
                    print("⌛ No immediate success message. Waiting 10s...")
                    time.sleep(10)
                    page.screenshot(path=f"videos/{prefix}_04_final.png")
                
                results[site] = "PASS" if found else "TIMEOUT/CHECK_SCREENSHOT"
                
            except Exception as e:
                print(f"❌ ERROR on {site}: {e}")
                results[site] = "FAIL"
            finally:
                if 'context' in locals(): context.close()
                if 'browser' in locals(): browser.close()

    print("\n" + "="*60)
    print("FINAL TEST MATRIX")
    print("="*60)
    for site, status in results.items():
        print(f"{site:40} | {status}")
    print("="*60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--site", required=True, help="Comma-separated list of sites")
    parser.add_argument("--username", default=None)
    parser.add_argument("--headless", action="store_true")
    args = parser.parse_args()
    
    username = args.username or f"test_{int(time.time())}"
    run_tests(args.site, username, args.headless)
