tell application "System Events"
    set output to ""
    
    set procs to {"System Settings", "SecurityAgent", "UserNotificationCenter", "CoreServicesUIAgent"}
    
    repeat with pName in procs
        if exists process pName then
            set output to output & "Process: " & pName & "\n"
            tell process pName
                set output to output & "Windows: " & (name of every window) & "\n"
                
                repeat with w in (every window)
                   try
                       set wName to name of w
                       set output to output & "  Window: " & wName & "\n"
                       set output to output & "    Buttons: " & (name of every button of w) & "\n"
                       -- Try getting sheets/groups
                       if exists (sheet 1 of w) then
                          set output to output & "    Sheet 1: " & (name of every button of sheet 1 of w) & "\n"
                       end if
                   end try
                end repeat
            end tell
        else
            set output to output & "Process " & pName & " not found\n"
        end if
    end repeat
    
    return output
end tell
