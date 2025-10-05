Source: https://www.derekseaman.com/2025/08/how-to-synology-iscsi-lun-for-proxmox-backup-server-datastore.html

This is a script for a preinstalled Proxmox Backup Server 4.x in a VM on a Proxmox VE host. ( Important NOT an LXC container )
You have to run the Proxmox Backup Server in a full blown VM environment.

I wanted to make a script which made a complete setup for my Synology server, since I have had many issues with NFS with the correct permissions. 

So what it basically does: 

1: Update your Proxmox Backup server
2: Remove the enterprise repo and remove no subscription nag
3: Install iSCSI via Dereks iSCSI_mount script
4: Reboots the server and you are all good to go .

I borrowed his scripts and want to try to build everything into a "One Installer to Rule them All" .. :P 

So all his hard work - a huge thanks for an alternative way to do backup to your Synology nas, instead of using NFS share to Proxmox Backup Server.

My first "automated" script, so please bare with me. ( which probably can use some huge fine tunings :) )

Guide for iSCSI lun on the Synology server: 

Synology iSCSI LUN Creation

1: Login to your Synology and open the SAN Manager application.

2: On the left click on iSCSI, then "Add".

3: Give the iSCSI target a description a name then click Next. 

4: Click Next on Create a new LUN.

5: Enter a LUN name, description, location, and size. Select Thin Provisioning, and check the Space reclamation box. 

6: Click Next then click Done.

7: On the left click on LUN. Edit the LUN, click on the Cache tab, and check the FUA/Sync box. Click Save.

8: Download the script via git clone https://github.com/MorphyDK/pbs-postinstaller.git

MorphyDK

