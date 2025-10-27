# NOTE: Still in progress  
## The goal: make zfs + debian enjoyable (as it should be)  
## Current projects:  
### - easy way to install luks + zfs onto a mirror for the base OS (SSDs)  
  - the simple way is to use a debian live iso + clone and run the live-iso scripts  
  - the end goal would be the creation of a custom ISO (currently failing at this)  
  - tpm autounlock should be an option (so the drives automatically decrypt on boot)  
  - being secureboot friendly is a goal as well (mok password is "debian-zfs")  
### - easy way of managing zfs (using cockpit extensions from 45Drives)  
  - the old way is just cloning https://github.com/45Drives/cockpit-zfs-manager (I currently use this)  
  - the new way I am testing (openzfs 2.0+) is currently being built through github actions from https://github.com/45Drives/cockpit-zfs  
  - on Debian Bookworm:  
sudo install -d -m 0755 /usr/share/keyrings  
curl -fsSL https://<OWNER>.github.io/<REPO>/KEY.gpg | sudo tee /usr/share/keyrings/<REPO>-archive-keyring.gpg >/dev/null  
echo "deb [signed-by=/usr/share/keyrings/<REPO>-archive-keyring.gpg] https://<OWNER>.github.io/<REPO> bookworm main" | sudo tee /etc/apt/sources.list.d/<REPO>.list  
sudo apt update  
sudo apt install cockpit-zfs  

Grateful for these projects:  
https://github.com/45Drives/cockpit-zfs-manager  
https://github.com/45Drives/cockpit-zfs  
https://github.com/openzfs/zfs  
https://openzfs.github.io/openzfs-docs/Getting%20Started/Debian/index.html  
