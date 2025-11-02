#!/bin/bash
# Identify your two SSDs via /dev/disk/by-id/*
ls -l /dev/disk/by-id

export DISK1="/dev/disk/by-id/PUT-YOUR-FIRST-DISK-ID"
export DISK2="/dev/disk/by-id/PUT-YOUR-SECOND-DISK-ID"

# Required secrets (non-interactive). Use strong secrets!
export LUKS_PASSPHRASE='Correct-Horse-Battery-Staple'
export USERNAME='coolname'
export USER_PASSWORD='ChangeMe'

# Optional customizations (defaults shown):
export HOSTNAME='debian'
export TIMEZONE='Etc/UTC'
export LOCALE='en_US.UTF-8'
export BOOT_POOL_SIZE='2G'
export CREATE_SWAP='no'
export SWAP_SIZE='4G'
export REBOOT_WHEN_DONE='yes'

# then run as root: bash ./zfs-grub-secureboot.sh
