This is a script for a preinstall Proxmox Backup Server 4.x in a VM on a Proxmox VE host. 
You have to run the Proxmox Backup Server in a full blown VM environment and not as a LXC container.

I wanted to make a script which made a complete setup for my Synology server, since I have had many issues with NFS with the correct permissions.

After a bit googleling - I stumpled over Derek Seaman: 

https://www.derekseaman.com/2025/08/how-to-synology-iscsi-lun-for-proxmox-backup-server-datastore.html

I borrow his scripts and want to try to build everything into a "One Installer to Rule them All" .. :P 

So all his hard work - a huge thanks for an alternative way to do backup to your Synology nas, instead of using NFS share to Proxmox Backup Server.

My first "automated" script, so please bare with me. ( which probably can use some huge fine tunings :) )

Not complete done yet, but hopefully im getting there.

MorphyDK

