import os

with open("cmd/virtual-fido/main.go", "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    # 1. Add Darwin case to onlineOnlyCmd
    if 'case transport.ModeUSBIP, transport.ModeUSBIPWin2:' in line:
        # Preserve leading tabs
        indent = line[:line.find('case')]
        new_lines.append(f"{indent}case transport.ModeDarwin:\n")
        new_lines.append(f"{indent}\treturn runOnlineDarwin()\n")
        new_lines.append(line)
    
    # 2. Add auto-approve flag to offlineOnlyCmd
    elif 'cmd.Flags().StringVar(&countersPath, "counters", "", "path to encrypted counter store (optional; defaults to time-based)")' in line:
        new_lines.append(line)
        indent = line[:line.find('cmd')]
        new_lines.append(f'{indent}cmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "Auto-approve all requests")\n')
    
    # 3. Add autoApprove var before runOfflineVault
    elif 'func runOfflineVault(seedFile, vaultPath string) error {' in line:
        new_lines.append("var autoApprove bool\n\n")
        new_lines.append(line)
    
    # 4. Update runOfflineVault logic
    elif 'approver := promptApprover{}' in line:
        indent = line[:line.find('approver')]
        new_lines.append(f'{indent}approver := promptApprover{{alwaysApprove: autoApprove}}\n')
    
    elif 'if !airgap.PromptYesNo("Approve? (Y/n)") {' in line:
        indent = line[:line.find('if')]
        new_lines.append(f'{indent}if !autoApprove && !airgap.PromptYesNo("Approve? (Y/n)") {{\n')
    
    else:
        new_lines.append(line)

with open("cmd/virtual-fido/main.go", "w") as f:
    f.writelines(new_lines)
