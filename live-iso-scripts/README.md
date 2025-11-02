There are two main options to choose from  
The zfs implementation is the same - LUKS + zfs on root  
The bootloader implementation is different:  

Option 1: Ol' reliable  
GRUB + shim + secureboot with Microsoft keys  

Option 2: The newest hot stuff  
Systemdboot + UKI only + secureboot with custom keys - no Microsoft dependency at all  
Requirements: go to bios -> secureboot settings -> enable setup mode  

Some notes:  
I think you can do custom signing with grub (probably remove shim as its not needed and sign everything with custom keys)  
I was curious however to test  

The TPM implementation:  
there are 24 PCRs that one can optionally bind (numbers 0-23).  
The minimum for Microsoft secureboot is to bind 7,14. (optional ones that I believe increase security without too much headache: 1, 8)  
The minimum for custom keys is 7, 11.  (optional ones that I believe increase security without too much headache: 1, 12)     

Description of the PCR values, sources below  
PCR 1: Core system firmware data/host platform configuration; typically contains serial and model numbers  
PCR 7: Secure Boot state (whether enabled or not)  
PCR 8: Commands and kernel command line (grub)   
PCR 11: All components of unified kernel images (UKIs)   
PCR 12: Kernel command line, system credentials and system configuration images (systemdboot)  
PCR 14: “MOK” certificates and hashes  

Sources:  
https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/  
https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-PFP-Version-1.06-Revision-49_31July2023.pdf
