# fail2ban-fortigate
Fail2Ban code to update Fortigate rules

Scripts and configuration files I wrote up to allow fail2ban work with Fortigate Firewalls.

Other examples I found online used expect scripts, the problem with them is that if you 
have a lot of ban activity, the Fortigate single threads the SSH Logins, so you have
expect scripts timing out and either bans not getting done or bans not getting deleted.

Switching to use the Fortigate API fixes this issue.

Only tested in CentOS 7, and FortiOS 5.4.7