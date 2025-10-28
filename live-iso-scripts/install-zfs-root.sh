#!/usr/bin/env bash
set -euo pipefail

# ========= User-configurable via environment =========
: "${DISK1:?Set DISK1 to /dev/disk/by-id/...}"
: "${DISK2:?Set DISK2 to /dev/disk/by-id/...}"
: "${LUKS_PASSPHRASE:?Set LUKS_PASSPHRASE to the LUKS passphrase}"
: "${ROOT_PASSWORD:?Set ROOT_PASSWORD to the root account password}"
: "${USERNAME:?Set USERNAME to the name of the normal user to create}"
: "${USER_PASSWORD:?Set USER_PASSWORD to the user account password}"

HOSTNAME="${HOSTNAME:-debian}"
TIMEZONE="${TIMEZONE:-Etc/UTC}"
LOCALE="${LOCALE:-en_US.UTF-8}"
BOOT_POOL_SIZE="${BOOT_POOL_SIZE:-2G}"   # See guide note re multiple kernels/snapshots
CREATE_SWAP="${CREATE_SWAP:-no}"
SWAP_SIZE="${SWAP_SIZE:-4G}"
REBOOT_WHEN_DONE="${REBOOT_WHEN_DONE:-yes}"

# ========= Derived / constants =========
export DEBIAN_FRONTEND=noninteractive
LIVE_MNT="/mnt"

# Ensure we're on Debian 12 live media and have networking
command -v apt >/dev/null

# Basic safety checks
for d in "$DISK1" "$DISK2"; do
  [[ -b "$d" ]] || { echo "Not a block device: $d"; exit 1; }
done
if [[ "$DISK1" == "$DISK2" ]]; then
  echo "DISK1 and DISK2 must be different."; exit 1
fi

echo ">>> This WILL ERASE: $DISK1 and $DISK2"
sleep 2

# Detect firmware mode
if [[ -d /sys/firmware/efi ]]; then
  BOOT_MODE="uefi"
else
  BOOT_MODE="bios"
fi
echo ">>> Detected boot mode: $BOOT_MODE"

# 0) Prepare live environment (repo + tools)
echo ">>> Preparing live environment..."
apt update
apt install --yes debootstrap gdisk zfsutils-linux cryptsetup dosfstools efibootmgr

# 1) Wipe + partition both disks per OpenZFS Bookworm guide
partition_disk() {
  local D="$1"
  echo ">>> Partitioning $D"
  swapoff --all || true
  sgdisk --zap-all "$D"
  # BIOS (optional; harmless on UEFI-only systems)
  sgdisk -a1 -n1:24K:+1000K -t1:EF02 "$D" || true
  # UEFI ESP
  sgdisk -n2:1M:+512M   -t2:EF00 "$D"
  # bpool (unencrypted; GRUB-readable)
  sgdisk -n3:0:+"$BOOT_POOL_SIZE" -t3:BF01 "$D"
  # rpool in LUKS (Linux LUKS code 8309)
  sgdisk -n4:0:0        -t4:8309 "$D"
  partprobe "$D"
}
partition_disk "$DISK1"
partition_disk "$DISK2"

# 2) Create LUKS on both disks' part4 and open as luks1/luks2
echo ">>> Creating and opening LUKS containers..."
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksFormat -q -c aes-xts-plain64 -s 512 -h sha256 "${DISK1}-part4" --key-file -
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksFormat -q -c aes-xts-plain64 -s 512 -h sha256 "${DISK2}-part4" --key-file -
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksOpen   "${DISK1}-part4" luks1 --key-file -
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksOpen   "${DISK2}-part4" luks2 --key-file -

# 3) Create pools (bpool unencrypted; rpool mirrored on LUKS)
echo ">>> Creating bpool (mirror) with GRUB compatibility..."
zpool create \
  -o ashift=12 \
  -o autotrim=on \
  -o compatibility=grub2 \
  -o cachefile=/etc/zfs/zpool.cache \
  -O devices=off \
  -O acltype=posixacl -O xattr=sa \
  -O compression=lz4 \
  -O normalization=formD \
  -O relatime=on \
  -O canmount=off -O mountpoint=/boot -R "$LIVE_MNT" \
  bpool mirror \
    "${DISK1}-part3" \
    "${DISK2}-part3"

echo ">>> Creating rpool (mirror) inside LUKS..."
zpool create \
  -o ashift=12 \
  -o autotrim=on \
  -O acltype=posixacl -O xattr=sa -O dnodesize=auto \
  -O compression=lz4 \
  -O normalization=formD \
  -O relatime=on \
  -O canmount=off -O mountpoint=/ -R "$LIVE_MNT" \
  rpool mirror \
    /dev/mapper/luks1 \
    /dev/mapper/luks2

# 4) Dataset layout (per guide)
echo ">>> Creating datasets..."
zfs create -o canmount=off -o mountpoint=none rpool/ROOT
zfs create -o canmount=noauto -o mountpoint=/ rpool/ROOT/debian
zfs mount rpool/ROOT/debian

zfs create -o mountpoint=/boot bpool/BOOT/debian

zfs create                       rpool/home
zfs create -o mountpoint=/root   rpool/home/root
chmod 700 "$LIVE_MNT/root"
zfs create -o canmount=off       rpool/var
zfs create -o canmount=off       rpool/var/lib
zfs create                       rpool/var/log
zfs create                       rpool/var/spool
# optional datasets you may want; uncomment as desired:
# zfs create -o com.sun:auto-snapshot=false rpool/var/cache
# zfs create -o com.sun:auto-snapshot=false rpool/var/lib/nfs
# zfs create -o com.sun:auto-snapshot=false rpool/var/tmp && chmod 1777 "$LIVE_MNT/var/tmp"
# zfs create rpool/srv
# zfs create -o canmount=off rpool/usr && zfs create rpool/usr/local
# zfs create rpool/var/mail
# zfs create rpool/var/www

# Guard against known GRUB issues if bpool is snapshotted at top-level
zfs set com.sun:auto-snapshot=false bpool || true

# 5) Prepare base system
echo ">>> Bootstrap minimal Debian system..."
mkdir -p "$LIVE_MNT/run"; mount -t tmpfs tmpfs "$LIVE_MNT/run"; mkdir -p "$LIVE_MNT/run/lock"
debootstrap bookworm "$LIVE_MNT"
mkdir -p "$LIVE_MNT/etc/zfs"
cp /etc/zfs/zpool.cache "$LIVE_MNT/etc/zfs/"

# 6) Configure the new system in chroot
echo ">>> Chroot configuration..."
# Build sources.list
cat > "$LIVE_MNT/etc/apt/sources.list" <<'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free-firmware
deb http://deb.debian.org/debian-security bookworm-security main contrib non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free-firmware
EOF

# Bind mounts and chroot
mount --make-private --rbind /dev  "$LIVE_MNT/dev"
mount --make-private --rbind /proc "$LIVE_MNT/proc"
mount --make-private --rbind /sys  "$LIVE_MNT/sys"

# Pass variables into chroot
cat > "$LIVE_MNT/root/post-chroot.sh" <<CHROOT_SCRIPT
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Hostname & hosts
echo "$HOSTNAME" > /etc/hostname
grep -q '^127.0.1.1' /etc/hosts || echo "127.0.1.1       $HOSTNAME" >> /etc/hosts

# Locale & timezone (noninteractive)
apt update
apt install --yes locales keyboard-configuration console-setup
sed -i 's/^# *$LOCALE UTF-8/$LOCALE UTF-8/' /etc/locale.gen || echo "$LOCALE UTF-8" >> /etc/locale.gen
locale-gen
update-locale LANG=$LOCALE
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
apt install --yes tzdata
dpkg-reconfigure -f noninteractive tzdata

# Networking: pick first non-lo interface and set DHCP with ifupdown
IFACE=\$(ls /sys/class/net | grep -E '^(en|eth)' | head -n1 || true)
if [[ -n "\$IFACE" ]]; then
  mkdir -p /etc/network/interfaces.d
  cat > /etc/network/interfaces.d/\$IFACE <<EONI
auto \$IFACE
iface \$IFACE inet dhcp
EONI
fi

# Kernel + ZFS + cryptsetup (Debian package names)
apt install --yes linux-image-amd64 linux-headers-amd64
apt install --yes zfs-initramfs zfsutils-linux
echo 'REMAKE_INITRD=yes' > /etc/dkms/zfs.conf

# LUKS entries (both disks), using by-uuid and initramfs option
apt install --yes cryptsetup cryptsetup-initramfs
UUID1=\$(blkid -s UUID -o value ${DISK1}-part4)
UUID2=\$(blkid -s UUID -o value ${DISK2}-part4)
cat > /etc/crypttab <<EOCR
luks1 /dev/disk/by-uuid/\$UUID1 none luks,discard,initramfs
luks2 /dev/disk/by-uuid/\$UUID2 none luks,discard,initramfs
EOCR

# UEFI: format and mount ESP on DISK1; BIOS: handled later
if [[ "$BOOT_MODE" == "uefi" ]]; then
  apt install --yes dosfstools efibootmgr grub-efi-amd64 shim-signed
  mkdosfs -F 32 -n EFI ${DISK1}-part2
  mkdir -p /boot/efi
  UUID_ESP=\$(blkid -s UUID -o value ${DISK1}-part2)
  echo "/dev/disk/by-uuid/\$UUID_ESP /boot/efi vfat defaults 0 0" >> /etc/fstab
  mount /boot/efi
else
  apt install --yes grub-pc
fi

# Make systemd aware of ZFS mount ordering via zfs-list.cache
mkdir -p /etc/zfs/zfs-list.cache
: > /etc/zfs/zfs-list.cache/bpool
: > /etc/zfs/zfs-list.cache/rpool
(zed -F) & ZEDPID=\$!
sleep 3
zfs set canmount=on bpool/BOOT/debian
zfs set canmount=noauto rpool/ROOT/debian
sleep 2
kill \$ZEDPID || true
sed -Ei "s|/mnt/?|/|" /etc/zfs/zfs-list.cache/*

# Import bpool early at boot (service unit from the guide)
cat > /etc/systemd/system/zfs-import-bpool.service <<'EOS'
[Unit]
DefaultDependencies=no
Before=zfs-import-scan.service
Before=zfs-import-cache.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/zpool import -N -o cachefile=none bpool
ExecStartPre=-/bin/mv /etc/zfs/zpool.cache /etc/zfs/preboot_zpool.cache
ExecStartPost=-/bin/mv /etc/zfs/preboot_zpool.cache /etc/zfs/zpool.cache

[Install]
WantedBy=zfs-import.target
EOS
systemctl enable zfs-import-bpool.service

# Optional swap on ZVOL
if [[ "$CREATE_SWAP" == "yes" ]]; then
  zfs create -V "$SWAP_SIZE" -b \$(getconf PAGESIZE) -o compression=zle \
             -o logbias=throughput -o sync=always \
             -o primarycache=metadata -o secondarycache=none \
             -o com.sun:auto-snapshot=false rpool/swap
  mkswap -f /dev/zvol/rpool/swap
  echo "/dev/zvol/rpool/swap none swap discard 0 0" >> /etc/fstab
  echo "RESUME=none" > /etc/initramfs-tools/conf.d/resume
fi

# Minimal time sync
apt install --yes systemd-timesyncd

# GRUB: probe, initramfs, cmdline, install
grub-probe /boot || true
update-initramfs -c -k all
sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="root=ZFS=rpool\\/ROOT\\/debian"/' /etc/default/grub
# (Optional debug) remove 'quiet' and force console:
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' /etc/default/grub
grep -q '^GRUB_TERMINAL' /etc/default/grub || echo 'GRUB_TERMINAL=console' >> /etc/default/grub
update-grub

if [[ "$BOOT_MODE" == "uefi" ]]; then
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck --no-floppy
else
  grub-install ${DISK1}
  grub-install ${DISK2}
fi

# Accounts: single admin user, root login disabled
apt install --yes sudo

# Ensure sudo group exists (should be created by the sudo package, but be safe)
getent group sudo >/dev/null || groupadd sudo

# Create the only admin (non-root) user
useradd -m -s /bin/bash -G sudo,adm,cdrom,video,plugdev "$USERNAME"
echo "$USERNAME:$USER_PASSWORD" | chpasswd

# Lock the root account (no password logins as root)
passwd -l root

# If SSH is present later, forbid any root SSH login
if [ -f /etc/ssh/sshd_config ]; then
  sed -ri 's/^\s*#?\s*PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config
fi

# Snapshot initial state (optional)
zfs snapshot bpool/BOOT/debian@install || true
zfs snapshot rpool/ROOT/debian@install || true
CHROOT_SCRIPT
chmod +x "$LIVE_MNT/root/post-chroot.sh"

chroot "$LIVE_MNT" /usr/bin/env \
  DISK1="$DISK1" DISK2="$DISK2" \
  HOSTNAME="$HOSTNAME" TIMEZONE="$TIMEZONE" LOCALE="$LOCALE" \
  BOOT_MODE="$BOOT_MODE" CREATE_SWAP="$CREATE_SWAP" SWAP_SIZE="$SWAP_SIZE" \
  bash -eux /root/post-chroot.sh

# 7) Mirror the ESP and register a 2nd UEFI entry (if UEFI)
if [[ "$BOOT_MODE" == "uefi" ]]; then
  echo ">>> Mirroring ESP to second disk and adding efiboot entry..."
  chroot "$LIVE_MNT" bash -eux <<EOS
umount /boot/efi || true
dd if=${DISK1}-part2 of=${DISK2}-part2 bs=1M conv=fsync
efibootmgr -c -g -d ${DISK2} -p 2 -L "debian-2" -l '\\EFI\\debian\\grubx64.efi' || true
mount /boot/efi
EOS
fi

# 8) Cleanup: unmount and export pools
echo ">>> Cleaning up and exporting pools..."
mount | grep -v zfs | tac | awk '/\/mnt/ {print $3}' | xargs -r -i{} umount -lf {}
zpool export -a || true

echo ">>> Installation complete."
if [[ "$REBOOT_WHEN_DONE" == "yes" ]]; then
  echo "Rebooting..."
  reboot
fi
