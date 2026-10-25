on clickButton(uiElem, btnName)
    tell application "System Events"
        try
            if exists button btnName of uiElem then
                click button btnName of uiElem
                return true
            end if
        end try
        try
            set subElems to UI elements of uiElem
            repeat with subElem in subElems
                 if my clickButton(subElem, btnName) then return true
            end repeat
        end try
    end tell
    return false
end clickButton

on run argv
    set sudo_password to item 1 of argv
    repeat 30 times
        delay 1
        tell application "System Events"
            -- Handle "System Extension Blocked" Alert
            if exists process "UserNotificationCenter" then
               tell process "UserNotificationCenter"
                  if exists (window 1) then
                      if exists button "Open System Settings" of window 1 then
                          click button "Open System Settings" of window 1
                          delay 2
                      end if
                  end if
               tell end
            end if

            -- Proactively open Privacy & Security if not already processing an alert
            if not (exists process "System Settings") then
                 do shell script "open 'x-apple.systempreferences:com.apple.PrivacySecurity'"
                 delay 3
            end if

            -- Handle "System Settings" "Allow" button
            if exists process "System Settings" then
                tell process "System Settings"
                     set frontmost to true
                     if my clickButton(window 1, "Allow") then
                         -- Clicked Allow, now handle password prompt
                     end if
                     
                     -- Also handle "Modify Settings" button in prompt
                     if my clickButton(window 1, "Modify Settings") then
                     end if
                tell end
            end if

            -- Handle Password prompt (SecurityAgent)
            if exists (window 1 of process "SecurityAgent") then
                tell process "SecurityAgent"
                    try
                         set value of text field 1 of group 1 of window 1 to sudo_password
                         click button "OK" of group 2 of window 1
                    on error
                         keystroke sudo_password
                         keystroke return
                    end try
                tell end
                -- Don't exit repeat immediately, wait for processing
            end if
        tell end
    end repeat
end run
