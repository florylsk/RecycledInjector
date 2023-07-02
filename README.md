# RecycledInjector

## Description

(Currently) Fully Undetected same-process native/.NET assembly shellcode injector based on [RecycledGate](https://github.com/thefLink/RecycledGate) by thefLink, which is also based on HellsGate + HalosGate + TartarusGate to ensure undetectable native syscalls even if one technique fails.

To remain stealthy and keep entropy on the final executable low, do ensure that shellcode is always loaded externally since most AV/EDRs won't check for signatures on non-executable or DLL files anyway.

Important to also note that the fully undetected part refers to the loading of the shellcode, however, the shellcode will still be subject to behavior monotoring, thus make sure the loaded executable also makes use of defense evasion techniques (e.g., SharpKatz which features DInvoke instead of Mimikatz).

## Usage

```powershell
.\RecycledInjector.exe <path_to_shellcode_file>
```

## Proof of Concept

This proof of concept leverages [Terminator](https://github.com/ZeroMemoryEx/Terminator) by ZeroMemoryEx to kill most security solution/agents present on the system. It is used against Microsoft Defender for Endpoint EDR.

On the left we inject the Terminator shellcode to load the vulnerable driver and kill MDE processes, and on the right is an example of loading and executing Invoke-Mimikatz remotely from memory, which is not stopped as there is no running security solution anymore on the system.

![RecycledInjector](https://github.com/florylsk/RecycledInjector/assets/46110263/b3ae8ada-0e27-47b4-adeb-55ad89aef815)
