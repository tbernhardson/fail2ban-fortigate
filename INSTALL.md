Install fail2ban

Install & configure fail2ban on syslog server to block traffic at the fortigate firewall
Based on this Fortinet Forum note: https://forum.fortinet.com/tm.aspx?m=138845
And on https://github.com/eoprede/fortigate_api
Note: assumes you already have fail2ban installed and running

Prerequisites: python modules: requests 
Configure fail2ban
sudo cp -p /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo cp -p /etc/fail2ban/jail.local /etc/fail2ban/jail.local.stock
sudo mkdir /etc/fail2ban/scripts
copy the file fortigate-ZONE-add.py to /etc/fail2ban/scripts changing ZONE to your Network Interface/Zone Name (repeat for each Zone)
copy the file fortigate-ZONE-delete.py to /etc/fail2ban/scripts changing ZONE to your Network Interface/Zone Name (repeat for each zone)
Edit each file and update as noted in the file.
Copy fortigate-ZONE.conf to /etc/fail2ban/action.d changing ZONE to your Network Interface/Zone Name (repeat for each Zone)
Edit each file and update as noted in the file.
Copy fortigate-ZONE-deny.conf to /etc/fail2ba/filter.d changing ZONE to your Network Inerface/Zone Name (repeat for each Zone)
Edit each file and update as noted in the file.
Copy 01-fortigate.conf to /etc/fail2ban/jail.d
Edit the file and update as noted in the file.

Setup the Fortigate
Log into your firewall
Create an Administrative user (fail2ban), set a password & only allow it to logon from Your Log Server IP Address
Create an Admin Profile (fail2ban_admin) that is only allowed to change Policy & Address Configuration
Assign the fail2ban user to that Profile
Setup an Address Group for your Internal/Trusted Zone (Note: names must match what you configured in the add & delete python scripts).
	Name = Trust_IP_Blacklist
	Members (some Internal Address that should Never come from Internet)
Setup an Address Group
	Name = All-VIPs
	Member = All Virtual IP’s
Setup a Policy/Rule in Untrust to Trust
       Name = IP_Trust_Blacklist
	Incoming Interface = Untrust Interface
	Outgoing Interface = Trusted Interface
	Source = Trust_IP_Blacklist
	Destination = ALL-VIPs
	Service = All
	Action = Deny
Setup an Address Group
	Name = DMZ_IP_Blacklist
	Members (some Internal Address that should Never come from Internet)
Setup a Policy/Rule in Untrust to DMZ
Name = IP_DMZ_Blacklist
	Incoming Interface = Untrust Interface
	Outgoing Interface = DMZ Interface
	Source = DMZ_IP_Blacklist
	Destination = ALL-VIPs
	Service = All
	Action = Deny

Start fail2ban
systemctl start fail2ban
tail -f /var/log/fail2ban.log

Check Configuration
sudo fail2ban-client -i
status
This should list all the jails 
For each jail: status <Jail Name>
Will list the status of the jail, the filter status and the action status
