# About

bootlicker is a legacy, extensible UEFI firmware rootkit targeting vmware hypervisor virtual machines. It is designed to achieve initial code execution within the context of the windows kernel, regardless of security settings configured.

## Architecture

![](https://i.imgur.com/ONRLJZe.png)

vmvware-bootkit takes its design from the legacy CosmicStrain, MoonBounce, and ESPECTRE rootkits to achive arbitrary code excution without triggering patchguard or other related security mechanisms.

After initial insertion into a UEFI driver firmware using the the [injection utility](scripts/inject.py), the shellcodes [EfiMain](bootkit/EfiMain.c) achieves execution as the host starts up, and inserts a hook into the UEFI firmware's [ExitBootServices routine](bootkit/ExitBootServices.c). The ExitBootServices routine will then, on execution, find the source caller of the function, and if it matches WinLoad.EFI, attempts to find the unexported winload.efi!OslArchTransferToKernel routine, which will allow us to attack the booting kernel before it achieves its initial execution.

Once [OslArchTransferToKernel](bootkit/OslArchTransferToKernel.c) executes, it will search for the ACPI.SYS driver, find the `.rsrc` PE section, and inject a small stager shellcode entrypoint called [DrvMain](bootkit/DrvMain.c) to copy over a larger payload that will act as our kernel implant.

### Resources

Entirely based upon d_olex / cr4sh's [DmaBackdoorBoot](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorBoot)
