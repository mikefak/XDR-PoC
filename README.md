# XDR-LabSetup.sh

*Description*

This program is used in conjunction with the PoC writeup. It is used as a practical way to simply establish the lab environment necessary to exploit CVE-2021-3560 and view how Cortex XDR captures such events

*Options*
  1. Help: Display command information and about

  2. Initiate Checklist Scan: Go through checklist of pre-requisites required for exploit to
    work. Examines operating system, polkit version, package installations, a running ssh instance, the users uid permissions, 
    and a valid installation of the Cortex XDR agent.

  3. Install required packages: Looks for and install the ssh, gnome-control-center, and accountsservice packages. These are essential to run the PoC on the host. If all of the packages are installed, no further action will be taken

  4. Guide to initiate exploit: Prints guide to initiate exploit based on information by original CVE discoverer and security researcher Kevin Backhouse. Source: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/

*Original Post*

https://live.paloaltonetworks.com/t5/cortex-xdr-discussions/cortex-xdr-poc-lab-ft-cve-2021-3560/td-p/513649

# Cortex XDR PoC: Monitoring Malicious Chrome Extensions

*Description*

This program is used alongside the "Script Execution" section of the Action Center within Cortex XDR. It serves as a practical way to extract extension information from endpoints, typically in addition with information retrieved from an XQL widget. A more thorough guide on the workflow can be found on the original post.

*Original Post*
https://live.paloaltonetworks.com/t5/cortex-xdr-discussions/cortex-xdr-poc-monitoring-malicious-chrome-extensions/m-p/519888
