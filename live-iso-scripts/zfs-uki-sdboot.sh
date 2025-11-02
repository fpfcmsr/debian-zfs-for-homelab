#!/usr/bin/env bash
# install-zfs-uki-owner.sh
# Debian Trixie ZFS-on-root (mirror) with LUKS, systemd-boot, UKI-only boot, *owner* Secure Boot keys (no Microsoft).
# Run from a Debian Trixie live ISO with firmware in UEFI Secure Boot *Setup Mode* (factory keys cleared).

set -euo pipefail

# ===== Sanity & prerequisites =================================================
require_root() { [[ ${EUID:-0} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }; }
require_uefi() { [[ -d /sys/firmware/efi ]] || { echo "UEFI not detected. Aborting." >&2; exit 1; }; }
say() { echo -e "\n>>> $*\n"; }
ok()  { echo -e "    OK: $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

require_root
require_uefi

# Ensure efivarfs is mounted so we can detect Setup Mode and enroll keys
if [[ ! -r /sys/firmware/efi/efivars/SetupMode-* ]]; then
  mkdir -p /sys/firmware/efi/efivars || true
  mount -t efivarfs efivarfs /sys/firmware/efi/efivars || true
fi
SETUP_MODE=$(od -An -t u1 /sys/firmware/efi/efivars/SetupMode-* 2>/dev/null | awk '{print $1}' | tail -n1 || echo "")
if [[ "$SETUP_MODE" != "1" ]]; then
  echo "Firmware is NOT in Secure Boot Setup Mode (SetupMode != 1)." >&2
  echo "Enter firmware setup, clear factory keys to enter Setup Mode, then rerun." >&2
  exit 1
fi

# ===== Global defaults ========================================================
HOSTNAME="debian"
TIMEZONE="${TIMEZONE:-Etc/UTC}"
LOCALE="${LOCALE:-en_US.UTF-8}"

# ===== Disk selection =========================================================
pick_two_disks() {
  say "Scanning disks…"
  mapfile -t LINES < <(lsblk -d -e 7 -o NAME,SIZE,MODEL,TYPE -nr | awk '$4=="disk"')
  ((${#LINES[@]}>=2)) || die "Need at least two disks."
  echo "Available disks:"
  i=1
  declare -gA IDX2DEV
  for line in "${LINES[@]}"; do
    name=$(awk '{print $1}' <<<"$line")
    size=$(awk '{print $2}' <<<"$line")
    model=$(awk '{$1=$2=$3=""; sub(/^   /,""); print}' <<<"$line")
    path="/dev/$name"
    byid=$(readlink -f /dev/disk/by-id/* 2>/dev/null | grep -E "/$name$" | head -n1 || true)
    [[ -n "$byid" ]] || byid="$path"
    printf "  [%d] %-14s %-10s %s\n" "$i" "$path" "($size)" "$model"
    IDX2DEV[$i]="$byid"
    ((i++))
  done
  read -rp "Enter number for DISK #1: " a
  read -rp "Enter number for DISK #2: " b
  [[ -n "${IDX2DEV[$a]:-}" && -n "${IDX2DEV[$b]:-}" && "$a" != "$b" ]] || die "Invalid selection."
  DISK1="${IDX2DEV[$a]}"
  DISK2="${IDX2DEV[$b]}"
  say "Selected: $DISK1 and $DISK2"
}

# ===== User info ==============================================================
prompt_user_info() {
  read -rp "Hostname [debian]: " HOSTNAME; HOSTNAME=${HOSTNAME:-debian}
  while :; do
    read -rp "Admin username: " USERNAME
    [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]*$ ]] && break || echo "Invalid username."
  done
  while :; do
    read -rs -p "Admin password: " USER_PASSWORD; echo
    read -rs -p "Confirm admin password: " USER_PASSWORD2; echo
    [[ "$USER_PASSWORD" == "$USER_PASSWORD2" && -n "$USER_PASSWORD" ]] && break || echo "Passwords mismatch."
  done
  while :; do
    read -rs -p "LUKS recovery passphrase: " LUKS_PASSPHRASE; echo
    read -rs -p "Confirm LUKS recovery passphrase: " LUKS_PASSPHRASE2; echo
    [[ "$LUKS_PASSPHRASE" == "$LUKS_PASSPHRASE2" && -n "$LUKS_PASSPHRASE" ]] && break || echo "Passphrases mismatch."
  done
}

# ===== Partition, LUKS, ZFS ===================================================
partition_disks() {
  say "Partitioning (GPT: ESP 512MiB + LUKS)… THIS WILL ERASE DATA."
  sleep 2
  for D in "$DISK1" "$DISK2"; do
    swapoff -a || true
    sgdisk --zap-all "$D"
    sgdisk -n1:1M:+512M -t1:EF00 "$D"   # ESP
    sgdisk -n2:0:0      -t2:8309 "$D"   # Linux LUKS
    partprobe "$D"
    ok "Partitioned $D"
  done
}

setup_luks() {
  say "Creating LUKS on both disks…"
  printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksFormat -q -c aes-xts-plain64 -s 512 -h sha256 "${DISK1}-part2" --key-file -
  printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksFormat -q -c aes-xts-plain64 -s 512 -h sha256 "${DISK2}-part2" --key-file -
  printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksOpen   "${DISK1}-part2" luks1 --key-file -
  printf '%s' "$LUKS_PASSPHRASE" | cryptsetup luksOpen   "${DISK2}-part2" luks2 --key-file -
  ok "Opened as /dev/mapper/luks1 and luks2"
}

setup_zfs() {
  say "Installing tools & creating ZFS rpool mirror…"
  apt-get update
  apt-get install -y --no-install-recommends \
    debootstrap gdisk zfsutils-linux zfs-dkms zfs-initramfs \
    cryptsetup cryptsetup-initramfs dosfstools efibootmgr \
    efitools sbsigntool openssl sbverify systemd-ukify rsync
  apt-get install -y --no-install-recommends systemd-boot || apt-get install -y --no-install-recommends systemd-boot-efi

  zpool create \
    -o ashift=12 -o autotrim=on \
    -O acltype=posixacl -O xattr=sa -O dnodesize=auto \
    -O compression=lz4 -O normalization=formD -O relatime=on \
    -O canmount=off -O mountpoint=/ -R /mnt \
    rpool mirror /dev/mapper/luks1 /dev/mapper/luks2

  zfs create -o canmount=off -o mountpoint=none rpool/ROOT
  zfs create -o canmount=noauto -o mountpoint=/ rpool/ROOT/debian
  zfs mount rpool/ROOT/debian
  zfs create                       rpool/home
  zfs create -o mountpoint=/root   rpool/home/root && chmod 700 /mnt/root
  zfs create -o canmount=off       rpool/var
  zfs create -o canmount=off       rpool/var/lib
  zfs create                       rpool/var/log
  zfs create                       rpool/var/spool

  mkdir -p /mnt/etc/zfs && cp /etc/zfs/zpool.cache /mnt/etc/zfs/ || true
}

# ===== Bootstrap Debian Trixie ===============================================
bootstrap_trixie() {
  say "Bootstrapping Debian Trixie into /mnt…"
  debootstrap trixie /mnt
  cat > /mnt/etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free-firmware
deb http://deb.debian.org/debian-security trixie-security main contrib non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free-firmware
EOF
}

# ===== Chroot configuration ===================================================
bind_and_chroot() {
  mount --make-private --rbind /dev  /mnt/dev
  mount --make-private --rbind /proc /mnt/proc
  mount --make-private --rbind /sys  /mnt/sys

  cat > /mnt/root/post-chroot.sh <<'CHROOT'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
say(){ echo -e "\n[CHROOT] $*\n"; }

say "Base config (locale, timezone, network, hostname)…"
apt-get update
apt-get install -y locales keyboard-configuration console-setup tzdata ifupdown
sed -i 's/^# *'"$LOCALE"' UTF-8/'"$LOCALE"' UTF-8/' /etc/locale.gen || echo "$LOCALE UTF-8" >> /etc/locale.gen
locale-gen
update-locale LANG=$LOCALE
ln -sf "/usr/share/zoneinfo/$TIMEZONE" /etc/localtime
dpkg-reconfigure -f noninteractive tzdata
echo "$HOSTNAME" > /etc/hostname
grep -q '^127.0.1.1' /etc/hosts || echo "127.0.1.1   $HOSTNAME" >> /etc/hosts
IFACE=$(ls /sys/class/net | grep -E '^(en|eth)' | head -n1 || true)
if [ -n "$IFACE" ]; then
  mkdir -p /etc/network/interfaces.d
  cat > /etc/network/interfaces.d/$IFACE <<EONI
auto $IFACE
iface $IFACE inet dhcp
EONI
fi

say "Kernel, ZFS, crypto, tools…"
apt-get install -y linux-image-amd64 linux-headers-amd64
apt-get install -y zfs-initramfs zfsutils-linux zfs-dkms cryptsetup cryptsetup-initramfs
apt-get install -y efitools sbsigntool efibootmgr openssl sbverify systemd-ukify rsync
apt-get install -y systemd-boot || apt-get install -y systemd-boot-efi

# crypttab (unlock both LUKS in initramfs)
UUID1=$(blkid -s UUID -o value ${DISK1}-part2)
UUID2=$(blkid -s UUID -o value ${DISK2}-part2)
cat > /etc/crypttab <<EOCR
luks1 /dev/disk/by-uuid/$UUID1 none luks,discard,initramfs
luks2 /dev/disk/by-uuid/$UUID2 none luks,discard,initramfs
EOCR

say "ESP on first disk + bootctl…"
mkdosfs -F 32 -n EFI ${DISK1}-part1
mkdir -p /boot/efi
UUID_ESP=$(blkid -s UUID -o value ${DISK1}-part1)
echo "/dev/disk/by-uuid/$UUID_ESP /boot/efi vfat defaults 0 0" >> /etc/fstab
mount /boot/efi
bootctl install

say "UKI cmdline + kernel-install UKI layout…"
mkdir -p /etc/kernel
cat > /etc/kernel/cmdline <<EOCMD
root=ZFS=rpool/ROOT/debian rw
EOCMD
cat > /etc/kernel/install.conf <<EOI
layout=uki
EOI

# *** UKI-only enforcement: disable legacy loader entries completely ***
install -d -m 0755 /etc/kernel/install.d
cat > /etc/kernel/install.d/90-loaderentry.install <<'EOF'
#!/usr/bin/env bash
# Disable legacy loader entries; rely only on UKIs in EFI/Linux
exit 0
EOF
chmod 0755 /etc/kernel/install.d/90-loaderentry.install

say "Generate *owner* Secure Boot keys (PK/KEK/db), ESL/AUTH, and enroll (Setup Mode)…"
OWNER_DIR=/var/lib/secureboot/owner
install -d -m 0700 "$OWNER_DIR"
for name in PK KEK db; do
  if [ ! -f "$OWNER_DIR/$name.key" ]; then
    openssl req -new -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
      -subj "/CN=$(hostname -f) $name/" \
      -keyout "$OWNER_DIR/$name.key" -out "$OWNER_DIR/$name.crt"
    chmod 600 "$OWNER_DIR/$name.key" "$OWNER_DIR/$name.crt"
  fi
done
[ -f "$OWNER_DIR/guid.txt" ] || uuidgen > "$OWNER_DIR/guid.txt"
GUID=$(cat "$OWNER_DIR/guid.txt")
for name in PK KEK db; do
  cert-to-efi-sig-list -g "$GUID" "$OWNER_DIR/$name.crt" "$OWNER_DIR/$name.esl"
done
sign-efi-sig-list -g "$GUID" -k "$OWNER_DIR/PK.key" -c "$OWNER_DIR/PK.crt" PK  "$OWNER_DIR/PK.esl"  "$OWNER_DIR/PK.auth"
sign-efi-sig-list -g "$GUID" -k "$OWNER_DIR/PK.key" -c "$OWNER_DIR/PK.crt" KEK "$OWNER_DIR/KEK.esl" "$OWNER_DIR/KEK.auth"
sign-efi-sig-list -g "$GUID" -k "$OWNER_DIR/PK.key" -c "$OWNER_DIR/PK.crt" db  "$OWNER_DIR/db.esl"  "$OWNER_DIR/db.auth"

# Attempt owner-key enrollment (Setup Mode only)
efi-updatevar -e -f "$OWNER_DIR/db.esl"  db
efi-updatevar -e -f "$OWNER_DIR/KEK.esl" KEK
efi-updatevar      -f "$OWNER_DIR/PK.auth" PK

# DKMS auto-sign (ZFS etc.) with db key (use DER for kmodsign)
openssl x509 -in "$OWNER_DIR/db.crt" -outform DER -out "$OWNER_DIR/db.der"
DKMS_CONF=/etc/dkms/framework.conf
touch "$DKMS_CONF"; chmod 644 "$DKMS_CONF"
grep -q '^mok_signing_key=' "$DKMS_CONF" 2>/dev/null && sed -i "s|^mok_signing_key=.*|mok_signing_key=$OWNER_DIR/db.key|" "$DKMS_CONF" || echo "mok_signing_key=$OWNER_DIR/db.key" >> "$DKMS_CONF"
grep -q '^mok_certificate=' "$DKMS_CONF" 2>/dev/null && sed -i "s|^mok_certificate=.*|mok_certificate=$OWNER_DIR/db.der|" "$DKMS_CONF" || echo "mok_certificate=$OWNER_DIR/db.der" >> "$DKMS_CONF"
cat > /etc/dkms/sign_helper.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
KEY="/var/lib/secureboot/owner/db.key"
DER="/var/lib/secureboot/owner/db.der"
MOD="${1:?kernel module path}"
/usr/bin/kmodsign sha512 "$KEY" "$DER" "$MOD"
EOF
chmod 755 /etc/dkms/sign_helper.sh
grep -q '^sign_tool=' "$DKMS_CONF" 2>/dev/null || echo 'sign_tool="/etc/dkms/sign_helper.sh"' >> "$DKMS_CONF"

# ukify signing config for UKIs
cat > /etc/kernel/uki.conf <<EOU
[UKI]
SecureBootPrivateKey=$OWNER_DIR/db.key
SecureBootCertificate=$OWNER_DIR/db.crt
Cmdline=@/etc/kernel/cmdline
EOU

say "Build initramfs and create (signed) UKI…"
KVER=$(cd /lib/modules && ls -1 | sort -V | tail -n1)
update-initramfs -c -k "$KVER"
kernel-install add "$KVER" "/boot/vmlinuz-$KVER" "/boot/initrd.img-$KVER"

say "Sign sd-boot and any EFI loaders with db key…"
for f in \
  /boot/efi/EFI/systemd/systemd-bootx64.efi \
  /boot/efi/EFI/BOOT/BOOTX64.EFI \
  /boot/efi/EFI/debian/*.efi \
  /boot/efi/EFI/Linux/*.efi ; do
  [ -f "$f" ] || continue
  sbsign --key "$OWNER_DIR/db.key" --cert "$OWNER_DIR/db.crt" --output "$f" "$f"
done

say "Minimal loader config (UKI-only)…"
mkdir -p /boot/efi/loader
cat > /boot/efi/loader/loader.conf <<EOF
timeout 3
console-mode auto
editor no
EOF

# Remove any legacy loader entries if created by packages
rm -rf /boot/loader/entries 2>/dev/null || true
rm -rf /boot/efi/loader/entries 2>/dev/null || true
install -d -m 0755 /boot/efi/loader   # keep loader dir itself

# ---- Secure Boot auto-(re)sign helpers & hooks -----------------------------
say "Install auto-sign helpers & hooks…"
install -d -m 0755 /usr/local/lib/secureboot

cat > /usr/local/lib/secureboot/sb-sign-efi <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
KEY="/var/lib/secureboot/owner/db.key"
CRT="/var/lib/secureboot/owner/db.crt"
FILE="${1:?path to .efi or EFI-stub kernel}"
TMP="${FILE}.signed"
if sbverify --cert "$CRT" "$FILE" >/dev/null 2>&1; then
  exit 0
fi
sbsign --key "$KEY" --cert "$CRT" --output "$TMP" "$FILE"
owner=$(stat -c '%u:%g' "$FILE"); mode=$(stat -c '%a' "$FILE")
mv -f "$TMP" "$FILE"; chown "$owner" "$FILE" || true; chmod "$mode" "$FILE" || true
EOF
chmod 755 /usr/local/lib/secureboot/sb-sign-efi
ln -sf /usr/local/lib/secureboot/sb-sign-efi /usr/local/sbin/sb-sign-efi

cat > /usr/local/lib/secureboot/sb-resign-all <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ESP="$(mount | awk '/\/boot\/efi| \/efi /{print $3; exit}')"
SIGN="/usr/local/lib/secureboot/sb-sign-efi"
shopt -s nullglob
# Clean any legacy loader entries to enforce UKI-only
rm -f /boot/loader/entries/*.conf 2>/dev/null || true
rm -f "$ESP"/loader/entries/*.conf 2>/dev/null || true
# (1) EFI loaders / boot managers
for f in \
  "$ESP"/EFI/systemd/systemd-bootx64.efi \
  "$ESP"/EFI/BOOT/BOOTX64.EFI \
  "$ESP"/EFI/debian/"grubx64.efi" "$ESP"/EFI/debian/"shimx64.efi" "$ESP"/EFI/debian/"mmx64.efi" "$ESP"/EFI/debian/"fallback.efi"
do
  [[ -f "$f" ]] && "$SIGN" "$f" || true
done
# (2) UKIs (systemd-stub images)
for f in "$ESP"/EFI/Linux/*.efi "$ESP"/EFI/*/*.efi; do
  [[ -f "$f" ]] && "$SIGN" "$f" || true
done
# (3) EFI-stub kernels in /boot (signed anyway, not surfaced by sd-boot without entries)
for f in /boot/vmlinuz-*; do
  [[ -f "$f" ]] && "$SIGN" "$f" || true
done
# (4) Memtest (optional)
for f in /boot/memtest86+*.efi "$ESP"/EFI/debian/memtest86+*.efi; do
  [[ -f "$f" ]] && "$SIGN" "$f" || true
done
EOF
chmod 755 /usr/local/lib/secureboot/sb-resign-all
ln -sf /usr/local/lib/secureboot/sb-resign-all /usr/local/sbin/sb-resign-all

# Second ESP sync helper
cat > /usr/local/sbin/sync-esps <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CONF="/etc/secureboot/esp-sync.conf"
if [[ ! -r "$CONF" ]]; then exit 0; fi
. "$CONF"
PRIMARY="${ESP_PRIMARY_MOUNT:-/boot/efi}"
SEC_UUID="${ESP_SECONDARY_UUID:-}"
SEC_MNT="${ESP_SECONDARY_MOUNT:-/boot/efi2}"
[[ -n "$SEC_UUID" ]] || exit 0
mountpoint -q "$PRIMARY" || exit 0
mkdir -p "$SEC_MNT"
DEV="/dev/disk/by-uuid/$SEC_UUID"
if ! mountpoint -q "$SEC_MNT"; then
  if ! mount -t vfat -o rw "$DEV" "$SEC_MNT" 2>/dev/null; then
    echo "[sync-esps] WARN: could not mount $DEV at $SEC_MNT" >&2
    exit 0
  fi
  trap 'umount -f "$SEC_MNT" || true' EXIT
fi
rsync -a --delete "$PRIMARY"/ "$SEC_MNT"/
sync
EOF
chmod 755 /usr/local/sbin/sync-esps

# Hooks
cat > /etc/kernel/postinst.d/zz-secureboot-sign <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
VER="${1:-}"; IMG="${2:-/boot/vmlinuz-${VER}}"
# Enforce UKI-only: nuke legacy entries if any package re-added them
rm -f /boot/loader/entries/*.conf 2>/dev/null || true
rm -f /boot/efi/loader/entries/*.conf 2>/dev/null || true
[[ -x /usr/local/sbin/sb-sign-efi   && -f "$IMG" ]] && /usr/local/sbin/sb-sign-efi "$IMG" || true
[[ -x /usr/local/sbin/sb-resign-all ]] && /usr/local/sbin/sb-resign-all || true
[[ -x /usr/local/sbin/sync-esps     ]] && /usr/local/sbin/sync-esps     || true
EOF
chmod 755 /etc/kernel/postinst.d/zz-secureboot-sign

install -d -m 0755 /etc/initramfs/post-update.d
cat > /etc/initramfs/post-update.d/zz-secureboot-sign <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
rm -f /boot/loader/entries/*.conf 2>/dev/null || true
rm -f /boot/efi/loader/entries/*.conf 2>/dev/null || true
[[ -x /usr/local/sbin/sb-resign-all ]] && /usr/local/sbin/sb-resign-all || true
[[ -x /usr/local/sbin/sync-esps     ]] && /usr/local/sbin/sync-esps     || true
EOF
chmod 755 /etc/initramfs/post-update.d/zz-secureboot-sign

cat > /etc/apt/apt.conf.d/90-secureboot-resign <<'EOF'
DPkg::Post-Invoke-Success {
  "rm -f /boot/loader/entries/*.conf 2>/dev/null || true";
  "rm -f /boot/efi/loader/entries/*.conf 2>/dev/null || true";
  "if [ -x /usr/local/sbin/sb-resign-all ]; then /usr/local/sbin/sb-resign-all || true; fi";
  "if [ -x /usr/local/sbin/sync-esps     ]; then /usr/local/sbin/sync-esps     || true; fi";
};
EOF
chmod 644 /etc/apt/apt.conf.d/90-secureboot-resign

# Initial resign
/usr/local/sbin/sb-resign-all || true

say "TPM2 auto-unlock for LUKS (PCR 1+7+11+12)…"
apt-get install -y systemd tpm2-tools || true
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=1+7+11+12 --tpm2-with-pin=no /dev/disk/by-uuid/$UUID1
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=1+7+11+12 --tpm2-with-pin=no /dev/disk/by-uuid/$UUID2

say "Admin user & SSH policy…"
apt-get install -y sudo openssh-server
getent group sudo >/dev/null || groupadd sudo
useradd -m -s /bin/bash -G sudo,adm,cdrom,video,plugdev "$USERNAME"
echo "$USERNAME:$USER_PASSWORD" | chpasswd
passwd -l root
sed -ri 's/^\s*#?\s*PermitRootLogin\s+.*/PermitRootLogin no/' /etc/ssh/sshd_config || true

say "Make zfs-list.cache for mount ordering (optional)…"
mkdir -p /etc/zfs/zfs-list.cache
: > /etc/zfs/zfs-list.cache/rpool
(zed -F) & ZEDPID=$!; sleep 3
zfs set canmount=noauto rpool/ROOT/debian
sleep 2; kill $ZEDPID || true
sed -Ei 's|/mnt/?|/|' /etc/zfs/zfs-list.cache/* || true

zfs snapshot rpool/ROOT/debian@install || true
CHROOT
  chmod +x /mnt/root/post-chroot.sh

  say "Entering chroot…"
  chroot /mnt /usr/bin/env \
    DISK1="$DISK1" DISK2="$DISK2" \
    HOSTNAME="$HOSTNAME" TIMEZONE="${TIMEZONE:-Etc/UTC}" LOCALE="${LOCALE:-en_US.UTF-8}" \
    USERNAME="$USERNAME" USER_PASSWORD="$USER_PASSWORD" \
    bash -eux /root/post-chroot.sh
}

# ===== ESP mirror & boot entry on 2nd disk ===================================
mirror_esp_and_bootentry() {
  say "Mirroring ESP to second disk and adding a secondary NVRAM entry…"
  umount /mnt/boot/efi || true
  mkdosfs -F 32 -n EFI ${DISK2}-part1
  UUID2=$(blkid -s UUID -o value ${DISK2}-part1)
  mkdir -p /mnt/esp1 /mnt/esp2
  mount ${DISK1}-part1 /mnt/esp1
  mount ${DISK2}-part1 /mnt/esp2
  rsync -a --delete /mnt/esp1/ /mnt/esp2/
  umount /mnt/esp1 /mnt/esp2
  chroot /mnt efibootmgr -c -g -d ${DISK2} -p 1 -L "debian-sdboot-2" -l '\\EFI\\systemd\\systemd-bootx64.efi' || true
  mount ${DISK1}-part1 /mnt/boot/efi
  mkdir -p /mnt/etc/secureboot
  if [[ -f /mnt/etc/secureboot/esp-sync.conf ]]; then
    sed -i "s/^ESP_SECONDARY_UUID=.*/ESP_SECONDARY_UUID=$UUID2/" /mnt/etc/secureboot/esp-sync.conf || true
  else
    cat > /mnt/etc/secureboot/esp-sync.conf <<EOF
ESP_PRIMARY_UUID=$(blkid -s UUID -o value ${DISK1}-part1)
ESP_PRIMARY_MOUNT=/boot/efi
ESP_SECONDARY_UUID=$UUID2
ESP_SECONDARY_MOUNT=/boot/efi2
EOF
  fi
  install -d -m 0755 /mnt/boot/efi2
  if ! grep -q "$UUID2" /mnt/etc/fstab 2>/dev/null; then
    echo "# Secondary ESP (noauto)" >> /mnt/etc/fstab
    echo "/dev/disk/by-uuid/$UUID2 /boot/efi2 vfat noauto 0 0" >> /mnt/etc/fstab
  fi
  chroot /mnt /usr/local/sbin/sync-esps || true
}

# ===== Cleanup ================================================================
cleanup_and_reboot() {
  say "Final cleanup…"
  mount | grep -v zfs | tac | awk '/\/mnt/ {print $3}' | xargs -r -i{} umount -lf {} || true
  zpool export -a || true
  say "Install complete."
  echo "Next steps:"
  echo "  1) In firmware, ENABLE Secure Boot (your owner keys are enrolled)."
  echo "  2) Boot normally — sd-boot will show **only** UKIs in EFI/Linux."
  echo "  3) LUKS will auto-unlock via TPM2 if PCR 7 & 14 match; passphrase is recovery."
  read -rp "Reboot now? [Y/n]: " ans; ans=${ans:-Y}
  [[ "$ans" =~ ^[Yy]$ ]] && reboot || true
}

# ===== Main ===================================================================
say "Debian Trixie ZFS-on-LUKS mirror with systemd-boot + UKI (UKI-only) and *owner* Secure Boot keys"
pick_two_disks
prompt_user_info
partition_disks
setup_luks
setup_zfs
bootstrap_trixie
bind_and_chroot
mirror_esp_and_bootentry
cleanup_and_reboot
