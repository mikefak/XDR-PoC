# XDR-PoC
Cortex XDR PoC ft. CVE-2021-3560

Description:
This program is used in conjunction with the PoC writeup. It is used as a practical
    way to simply establish the lab environment necessary to exploit CVE-2021-3560 and view 
    how Cortex XDR captures such events

Options:
  1. Help: Display command information and about

  2. Initiate Checklist Scan: Go through checklist of pre-requisites required for exploit to
    work. Examines operating system, polkit version, package installations, a running ssh instance, the users uid permissions, 
    and a valid installation of the Cortex XDR agent.

  3. Install required packages: Looks for and install the ssh, gnome-control-center, and accountsservice packages. These are essential to run the PoC on the host. If all of the packages are installed, no further action will be taken

  4. Guide to initiate exploit: Prints guide to initiate exploit based on information by original CVE discoverer and security researcher Kevin Backhouse. Source: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/

# Original Post

https://live.paloaltonetworks.com/t5/cortex-xdr-discussions/cortex-xdr-poc-lab-ft-cve-2021-3560/td-p/513649
