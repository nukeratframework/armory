import subprocess
import sys
import re

def get_sid_from_wmic(username=None, domain=None):
    if username:
        if domain:
            cmd = f'wmic useraccount where "Name=\'{username}\' and Domain=\'{domain}\'" get SID /value'
        else:
            cmd = f'wmic useraccount where "Name=\'{username}\'" get SID /value'
    else:
        cmd = 'wmic useraccount get Name,Domain,SID /format:csv'

    print(f"[*] Running: {cmd}")
    print(f"[*] Run this on a Windows box or through your beacon via shell/powershell")
    print()
    print("[*] Alternative commands you can run in beacon:")
    print()

    if username:
        print(f"  shell wmic useraccount where \"Name='{username}'\" get SID /value")
        print(f"  powershell ([System.Security.Principal.NTAccount]'{username}').Translate([System.Security.Principal.SecurityIdentifier]).Value")
        if domain:
            print(f"  powershell ([System.Security.Principal.NTAccount]('{domain}\\{username}')).Translate([System.Security.Principal.SecurityIdentifier]).Value")
    else:
        print("  shell wmic useraccount get Name,Domain,SID /format:csv")
        print("  powershell Get-WmiObject Win32_UserAccount | Select Name,SID")

    print()
    print("[*] For current user in beacon:")
    print("  powershell [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    print()
    print("[*] For administrator specifically:")
    print("  powershell ([System.Security.Principal.NTAccount]'Administrator').Translate([System.Security.Principal.SecurityIdentifier]).Value")

if __name__ == "__main__":
    username = sys.argv[1] if len(sys.argv) > 1 else None
    domain = sys.argv[2] if len(sys.argv) > 2 else None
    get_sid_from_wmic(username, domain)
