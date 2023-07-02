# RecycledGate

## Description

(Currently) Fully Undetected same-process native/.NET assembly shellcode injector based on [RecycledGate](https://github.com/thefLink/RecycledGate) by thefLink, which is also based on HellsGate + HalosGate + TartarusGate to ensure undetectable native syscalls even if one technique fails.

To remain stealthy and keep entropy on the final executable low, do ensure that shellcode is always loaded externally since most AV/EDRs won't check for signatures on non-executable or DLL files anyway.

Important to also note that the fully undetected part refers to the loading of the shellcode, however, the shellcode will still be subject to behavior monotoring, thus make sure the loaded executable also makes use of defense evasion techniques (e.g., SharpKatz which features DInvoke instead of Mimikatz).

## Usage

```powershell
.\RecycledInjector.exe <path_to_shellcode_file>
```
