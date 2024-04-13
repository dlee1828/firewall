# Firewall

This is a simple Linux firewall I built. 

The firewall is implemented as a loadable kernel module which utilizes the netfilter framework to register a 
hook function which gets called when network packets enter the machine. 

`firewall-interface/` contains a command line tool for configuring the firewall. 
I utilized the sysfs virtual file system to facilitate communication between the kernel module and 
user-space. 
