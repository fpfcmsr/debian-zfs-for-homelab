#!/usr/bin/env bash
set -euo pipefail

# Ensure prompts are visible on tty1 (we're started by systemd)
exec </dev/tty1 >/dev/tty1 2>&1 || true

# ========= Defaults (overridable via kernel cmdline) =========
HOSTNAME="${HOSTNAME:-debian}"
TIMEZONE="${TIMEZONE:-Etc/UTC}"
LOCALE="${LOCALE:-en_US.UTF-8}"
BOOT_POOL_SIZE="${BOOT_POOL_SIZE:-1G}"
CREATE_SWAP="${CREATE_SWAP:-no}"
SWAP_SIZE="${SWAP_SIZE:-4G}"
TPM2_PCRS_DEFAULT="7"   # conservative default

# ========= Helpers =========
log(){ echo -e "\n>>> $*\n"; }
karg(){ awk -v FS="[ =]" -v K="$1" '{for(i=1;i<=NF;i++) if($i==K){print $(i+1); exit}}' /proc/cmdline 2>/dev/null || true; }
first_or_default(){ local v; v="$(karg "$1")"; echo "${v:-$2}"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
confirm_match(){ local _var="$1" _p="$2" _s="${3:-no}" a b; while :; do
  if [ "$_s" = "yes" ]; then read -r -s -p "$_p: " a; echo; read -r -s -p "Confirm $_p: " b; echo
  else read -r -p "$_p: " a; read -r -p "Confirm $_p: " b; fi
  [ -n "$a" ] || { echo "Value cannot be empty."; continue; }
  [ "$a" = "$b" ] || { echo "Values do not match."; continue; }
  printf -v "$_var" '%s' "$a"; break
done; }
validate_username(){ [[ "$1" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; }

# ========= Kernel-arg overrides, then prompt =========
USERNAME="$(first_or_default zfs.user "")"
USER_PASSWORD="$(first_or_default zfs.user_pass "")"
LUKS_PASSPHRASE="$(first_or_default zfs.luks_pass "")"
TPM2_PCRS="$(first_or_default zfs.tpm2_pcrs "$TPM2_PCRS_DEFAULT")"

if [ -z "$USERNAME" ]; then
  while :; do
    read -r -p "Admin username (sudoer, root locked): " USERNAME || true
    validate_username "$USERNAME" && break || echo "Invalid username. Use lowercase letters/digits/[_-]."
  done
fi
[ -n "$USER_PASSWORD" ] || confirm_match USER_PASSWORD "Admin user password" yes
[ -n "$LUKS_PASSPHRASE" ] || confirm_match LUKS_PASSPHRASE "LUKS passphrase (recovery)" yes

log "Starting destructive install on two SSDs"

export DEBIAN_FRONTEND=noninteractive
LIVE_MNT="/mnt"
BOOT_MODE="bios"; [ -d /sys/firmware/efi ] && BOOT_MODE="uefi"; log "Boot mode: $BOOT_MODE"

# Tools in live ISO
apt-get update
apt-get install -y debootstrap gdisk zfsutils-linux cryptsetup dosfstools efibootmgr grub-pc grub-efi-amd64 shim-signed

# Detect exactly two non-removable SSDs (exclude live medium)
detect_two_ssds() {
  local live_src live_parent; live_src="$(findmnt -no SOURCE /run/live/medium 2>/dev/null || true)"
  [ -n "$live_src" ] && live_parent="$(lsblk -no PKNAME "$live_src" 2>/dev/null || true)"
  mapfile -t cand < <(lsblk -dn -o NAME,ROTA,TYPE,RM | awk '$2==0 && $3=="disk" {print $1}')
  local filtered=(); for n in "${cand[@]}"; do
    [[ "$n" =~ ^loop|^zram ]] && continue
    [ -n "$live_parent" ] && [ "$n" = "$live_parent" ] && continue
    filtered+=("$n")
  done
  [ "${#filtered[@]}" -eq 2 ] || die "Expected exactly 2 SSD disks, found: ${filtered[*]:-(none)}"
  DISK1="/dev/${filtered[0]}"; DISK2="/dev/${filtered[1]}"
}
detect_two_ssds; log "Targets: $DISK1, $DISK2"

# Prefer /dev/disk/by-id (safer)  (OpenZFS docs recommendation)
byid(){ local dev="$1" t; t="$(readlink -f "$dev")"; for p in /dev/disk/by-id/*; do [ "$(readlink -f "$p")" = "$t" ] && { echo "$p"; return; }; done; echo "$t"; }
DISK1_ID="$(byid "$DISK1")"; DISK2_ID="$(byid "$DISK2")"

# Partition per OpenZFS Bookworm: EF02, EF00(512M), BF01(bpool), 8309(LUKS)
partition_disk(){ local D="$1"; log "Partitioning $D"; swapoff --all || true
  sgdisk --zap-all "$D"
  sgdisk -a1 -n1:24K:+1000K -t1:EF02 "$D" || true
  sgdisk     -n2:1M:+512M   -t2:EF00 "$D"
  sgdisk     -n3:0:+"$BOOT_POOL_SIZE" -t3:BF01 "$D"
  sgdisk     -n4:0:0        -t4:8309 "$D"
  partprobe "$D"
}
partition_disk "$DISK1"; partition_disk "$DISK2"

# LUKS for rpool on both disks (luks1/luks2)
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksFormat -q -c aes-xts-plain64 -s 512 -h sha256 "${DISK1_ID}-part4" --key-file -
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksFormat -q -c aes-xts-plain64 -s 512 -h sha256 "${DISK2_ID}-part4" --key-file -
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksOpen   "${DISK1_ID}-part4" luks1 --key-file -
printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksOpen   "${DISK2_ID}-part4" luks2 --key-file -

# ZFS: bpool (GRUB-readable) and rpool (mirror over LUKS)
log "Creating bpool (mirror; GRUB compatibility)"
zpool create \
  -o ashift=12 -o autotrim=on -o compatibility=grub2 \
  -o cachefile=/etc/zfs/zpool.cache \
  -O devices=off -O acltype=posixacl -O xattr=sa \
  -O compression=lz4 -O normalization=formD -O relatime=on \
  -O canmount=off -O mountpoint=/boot -R "$LIVE_MNT" \
  bpool mirror "${DISK1_ID}-part3" "${DISK2_ID}-part3"

log "Creating rpool (mirror inside LUKS)"
zpool create \
  -o ashift=12 -o autotrim=on \
  -O acltype=posixacl -O xattr=sa -O dnodesize=auto \
  -O compression=lz4 -O normalization=formD -O relatime=on \
  -O canmount=off -O mountpoint=/ -R "$LIVE_MNT" \
  rpool mirror /dev/mapper/luks1 /dev/mapper/luks2

# Datasets (OpenZFS Bookworm)
zfs create -o canmount=off -o mountpoint=none rpool/ROOT
zfs create -o canmount=noauto -o mountpoint=/ rpool/ROOT/debian
zfs mount rpool/ROOT/debian
zfs create -o mountpoint=/boot bpool/BOOT/debian
zfs set com.sun:auto-snapshot=false bpool || true   # avoid GRUB issues with top-level snapshots
zfs create rpool/home
zfs create -o mountpoint=/root rpool/home/root && chmod 700 "$LIVE_MNT/root"
zfs create -o canmount=off rpool/var
zfs create -o canmount=off rpool/var/lib
zfs create rpool/var/log
zfs create rpool/var/spool

# Bootstrap Debian
log "debootstrap..."
mkdir -p "$LIVE_MNT/run"; mount -t tmpfs tmpfs "$LIVE_MNT/run"; mkdir -p "$LIVE_MNT/run/lock"
debootstrap bookworm "$LIVE_MNT"
mkdir -p "$LIVE_MNT/etc/zfs"; cp /etc/zfs/zpool.cache "$LIVE_MNT/etc/zfs/"

# APT sources (Bookworm + non-free-firmware)
cat > "$LIVE_MNT/etc/apt/sources.list" <<'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
EOF

# Bind mounts & enter chroot
mount --make-private --rbind /dev  "$LIVE_MNT/dev"
mount --make-private --rbind /proc "$LIVE_MNT/proc"
mount --make-private --rbind /sys  "$LIVE_MNT/sys"

cat > "$LIVE_MNT/root/post-chroot.sh" <<'CHROOT'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "$HOSTNAME" > /etc/hostname
grep -q '^127.0.1.1' /etc/hosts || echo "127.0.1.1       $HOSTNAME" >> /etc/hosts

apt update
apt install -y locales keyboard-configuration console-setup
sed -i 's/^# *'"$LOCALE"' UTF-8/'"$LOCALE"' UTF-8/' /etc/locale.gen || echo "$LOCALE UTF-8" >> /etc/locale.gen
locale-gen
update-locale LANG=$LOCALE
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
apt install -y tzdata
dpkg-reconfigure -f noninteractive tzdata

# Kernel + ZFS + crypto
apt install -y linux-image-amd64 linux-headers-amd64
apt install -y zfs-initramfs zfsutils-linux cryptsetup cryptsetup-initramfs
echo 'REMAKE_INITRD=yes' > /etc/dkms/zfs.conf

# Record LUKS UUIDs (for crypttab)
UUID1=$(blkid -s UUID -o value ${DISK1_ID}-part4)
UUID2=$(blkid -s UUID -o value ${DISK2_ID}-part4)

# Bootloader packages & ESP
if [ "$BOOT_MODE" = "uefi" ]; then
  apt install -y dosfstools efibootmgr grub-efi-amd64 shim-signed
  mkdosfs -F 32 -n EFI ${DISK1_ID}-part2
  mkdir -p /boot/efi
  UUID_ESP=$(blkid -s UUID -o value ${DISK1_ID}-part2)
  echo "/dev/disk/by-uuid/$UUID_ESP /boot/efi vfat defaults 0 0" >> /etc/fstab
  mount /boot/efi
else
  apt install -y grub-pc
fi

# zfs-list.cache + import guard for bpool
mkdir -p /etc/zfs/zfs-list.cache
: > /etc/zfs/zfs-list.cache/bpool
: > /etc/zfs/zfs-list.cache/rpool
(zed -F) & ZEDPID=$!
sleep 3
zfs set canmount=on bpool/BOOT/debian
zfs set canmount=noauto rpool/ROOT/debian
sleep 2
kill $ZEDPID || true
sed -Ei "s|/mnt/?|/|" /etc/zfs/zfs-list.cache/*

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
if [ "$CREATE_SWAP" = "yes" ]; then
  zfs create -V "$SWAP_SIZE" -b $(getconf PAGESIZE) -o compression=zle \
             -o logbias=throughput -o sync=always \
             -o primarycache=metadata -o secondarycache=none \
             -o com.sun:auto-snapshot=false rpool/swap
  mkswap -f /dev/zvol/rpool/swap
  echo "/dev/zvol/rpool/swap none swap discard 0 0" >> /etc/fstab
  echo "RESUME=none" > /etc/initramfs-tools/conf.d/resume
fi

# Cockpit / Podman / SSH / Intel microcode & firmware
apt install -y cockpit cockpit-podman podman uidmap slirp4netns fuse-overlayfs
apt install -y openssh-server
apt install -y intel-microcode firmware-misc-nonfree
systemctl enable ssh
systemctl enable cockpit.socket
grep -q "^$USERNAME:" /etc/subuid || echo "$USERNAME:100000:65536" >> /etc/subuid
grep -q "^$USERNAME:" /etc/subgid || echo "$USERNAME:100000:65536" >> /etc/subgid

# Single admin user; lock root
apt install -y sudo
getent group sudo >/dev/null || groupadd sudo
useradd -m -s /bin/bash -G sudo,adm,cdrom,video,plugdev "$USERNAME"
echo "$USER_PASSWORD" | chpasswd --crypt-method SHA512 "$USERNAME"
passwd -l root
if [ -f /etc/ssh/sshd_config ]; then
  sed -ri 's/^\s*#?\s*PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config
fi

# ---- TPM2 auto-unlock: systemd-cryptenroll preferred; clevis fallback ----
apt install -y tpm2-tools clevis clevis-luks clevis-tpm2 clevis-initramfs

tpmpresent=0
[ -e /dev/tpmrm0 ] && tpmpresent=1
if systemd-cryptenroll --tpm2-device=list 2>/dev/null | grep -q /dev/tpm; then tpmpresent=1; fi

if [ "$tpmpresent" -eq 1 ]; then
  TPM2_PCRS="${TPM2_PCRS:-$TPM2_PCRS_DEFAULT}"
  printf '%s' "$LUKS_PASSPHRASE" > /root/.luks-pass && chmod 600 /root/.luks-pass

  enroll_one() {
    local part="$1"
    if ! systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs="$TPM2_PCRS" \
                             --unlock-key-file=/root/.luks-pass "$part"; then
      clevis luks bind -d "$part" tpm2 "{\"pcr_ids\":\"$TPM2_PCRS\"}" -k /root/.luks-pass
    fi
  }
  enroll_one ${DISK1_ID}-part4
  enroll_one ${DISK2_ID}-part4

  cat > /etc/crypttab <<EOCR
luks1 /dev/disk/by-uuid/$UUID1 none luks,discard,initramfs,tpm2-device=auto,tpm2-pcrs=$TPM2_PCRS
luks2 /dev/disk/by-uuid/$UUID2 none luks,discard,initramfs,tpm2-device=auto,tpm2-pcrs=$TPM2_PCRS
EOCR
  update-initramfs -u -k all
  shred -u /root/.luks-pass
else
  cat > /etc/crypttab <<EOCR
luks1 /dev/disk/by-uuid/$UUID1 none luks,discard,initramfs
luks2 /dev/disk/by-uuid/$UUID2 none luks,discard,initramfs
EOCR
  update-initramfs -u -k all
fi

# GRUB & initramfs
grub-probe /boot || true
update-initramfs -c -k all
sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="root=ZFS=rpool\\/ROOT\\/debian"/' /etc/default/grub
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' /etc/default/grub
grep -q '^GRUB_TERMINAL' /etc/default/grub || echo 'GRUB_TERMINAL=console' >> /etc/default/grub
update-grub

if [ "$BOOT_MODE" = "uefi" ]; then
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck --no-floppy
else
  grub-install ${DISK1_ID}
  grub-install ${DISK2_ID}
fi

# Initial snapshots (optional)
zfs snapshot bpool/BOOT/debian@install || true
zfs snapshot rpool/ROOT/debian@install || true
CHROOT
chmod +x "$LIVE_MNT/root/post-chroot.sh"

# Pass variables into chroot
chroot "$LIVE_MNT" /usr/bin/env \
  DISK1_ID="$DISK1_ID" DISK2_ID="$DISK2_ID" \
  HOSTNAME="$HOSTNAME" TIMEZONE="$TIMEZONE" LOCALE="$LOCALE" \
  BOOT_MODE="$BOOT_MODE" CREATE_SWAP="$CREATE_SWAP" SWAP_SIZE="$SWAP_SIZE" \
  USERNAME="$USERNAME" USER_PASSWORD="$USER_PASSWORD" \
  TPM2_PCRS="$TPM2_PCRS" LUKS_PASSPHRASE="$LUKS_PASSPHRASE" \
  bash -eux /root/post-chroot.sh

# Mirror ESP to second disk (UEFI)
if [ "$BOOT_MODE" = "uefi" ]; then
  log "Mirroring ESP to second disk and adding a second boot entry"
  chroot "$LIVE_MNT" bash -eux <<EOS
umount /boot/efi || true
dd if=${DISK1_ID}-part2 of=${DISK2_ID}-part2 bs=1M conv=fsync
efibootmgr -c -g -d ${DISK2_ID%*-part*} -p 2 -L "debian-2" -l '\\EFI\\debian\\grubx64.efi' || true
mount /boot/efi
EOS
fi

# Cleanup & export pools
log "Cleaning up"
mount | grep -v zfs | tac | awk '/\/mnt/ {print $3}' | xargs -r -I{} umount -lf {}
zpool export -a || true

log "DONE. Remove the ISO and reboot."
reboot -f
