# About

bootlicker is a legacy, extensible UEFI firmware rootkit targeting vmware hypervisor virtual machines. It is designed to achieve initial code execution within the context of the windows kernel, regardless of security settings configured.

## Architecture

![](https://i.imgur.com/ONRLJZe.png)

bootlicker takes its design from the legacy CosmicStrain, MoonBounce, and ESPECTRE rootkits to achive arbitrary code excution without triggering patchguard or other related security mechanisms.

After initial insertion into a UEFI driver firmware using the the [injection utility](scripts/inject.py), the shellcodes [EfiMain](bootkit/EfiMain.c) achieves execution as the host starts up, and inserts a hook into the UEFI firmware's [ExitBootServices routine](bootkit/ExitBootServices.c). The ExitBootServices routine will then, on execution, find the source caller of the function, and if it matches WinLoad.EFI, attempts to find the unexported winload.efi!OslArchTransferToKernel routine, which will allow us to attack the booting kernel before it achieves its initial execution.

Once [OslArchTransferToKernel](bootkit/OslArchTransferToKernel.c) executes, it will search for the ACPI.SYS driver, find the `.rsrc` PE section, and inject a small stager shellcode entrypoint called [DrvMain](bootkit/DrvMain.c) to copy over a larger payload that will act as our kernel implant.

### Resources

Entirely based upon d_olex / cr4sh's [DmaBackdoorBoot](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorBoot)

### Epilogue

This code is apart of a larger project I've been working on that on / off in between burnout, like most of the concepts I've produced over the years under various aliases, will never see the light of day. Some of the code comments I've been to lazy to strip out that refer to unrelated functiaonlity, despite it being previously present. Do not expect this to work out of the box, some slight modifications are certainly necessary. 

I build these things purely for myself, and to advertise my skillsets. I'm a hobbyist engineer purely just trying to occupy my mind and keep myself mentally active. Professionally, I work as a consultant, and developer for a firm known as GuidePoint Security, where I've RE'd various exploits, software, mawlware, etc, anything I can get my hands on, for fun, in between work hours outside of billable work, purely because I find it more interesting than conducting another pentest or red-team.

I'm happy to answer any questions from anybody, despite my opinionated criticisms in public, I enjoy talking with people, and hearing other sides. Feel free to ask away. However: I won't be hand holding anyone through this. Best of luck, and have fun.
