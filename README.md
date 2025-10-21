# Debian Trixie ZFS Autoinstall ISO (two-SSD mirror, LUKS, TPM2 auto-unlock)

This repo builds a **text-only Debian 12 (trixie) Live ISO** that **automatically installs**:
- ZFS on root with **two-disk mirror** (bpool unencrypted, rpool in **LUKS**)
- **TPM2** auto-unlock if a TPM is present (fallback to passphrase)
- One **admin** user (prompted), **root login is locked**
- Extras: **openssh-server**, **cockpit** (+podman), **virtualization tools**, Intel/AMD microcode/firmware
- Secure Boot support (after install enroll mok with password "debian-zfs")

> ⚠️ **Destructive**: on boot, the installer **wipes two SSDs** (excluding the boot medium).

## Build it locally

```bash
sudo apt update
sudo apt install -y live-build debootstrap cdebootstrap squashfs-tools xorriso syslinux-common dosfstools
./build.sh
