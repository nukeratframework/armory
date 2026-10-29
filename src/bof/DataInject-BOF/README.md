# Data Inject BOF

A beacon object file implementation of the process injection proof-of-concept from my blog post [Control Flow Hijacking via Data Pointers](https://www.legacyy.xyz/defenseevasion/windows/2025/04/16/control-flow-hijacking-via-data-pointers.html).

Hijacks control flow via overwriting `combase.dll`'s Control Flow Guard function pointers called by COM proxying functions.

## Important Notes

- From my testing, `explorer.exe` is the current best candidate in terms of an easy triggering mechanism due to its heavy reliance on COM proxying. Would recommend experimenting.
- **Make sure** shellcode is 64-bit as this BOF only supports 64-bit beacons & target processes.
- This has only been tested on windows versions `Win10 21H2 (19044.5737)` & `Win11 24H2 (26100.3775)`.

## Usage

```
datainject <pid> <shellcode path>
```

### Examples

For sake of example, all process id's have been assumed to be `1234`

**Inject into explorer.exe, execute shellcode upon COM call (can be triggered by right clicking or opening file explorer)**
```
datainject 1234 C:\users\attacker\payloads\beacon_x64.bin
```

## References

- [Control Flow Hijacking via Data Pointers](https://www.legacyy.xyz/defenseevasion/windows/2025/04/16/control-flow-hijacking-via-data-pointers.html) - My blog post teaching my methodology to weaponising this.
- [Threadless Inject](https://github.com/CCob/ThreadlessInject) - The project that inspired me to start this research.