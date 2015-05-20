#PAM IHOSTS

This is a PAM (Pluggable Authentication Modules) that only allows login from certain hosts, either based on mac-address, ip-address, or their region looked as up in internet registrar stats files. pam_ihosts is not an authentication module, it's an account module.This means that it comes into play only after a user has already authenticated, and provides extra checks as to whether an authenticated user should be alowed to log in. This allows fine-grained control of which hosts a user is allowed to login from, with external logins being controlled by region and ip, and internal networks being controlled by mac-address or ip, the former allowing control even in DHCP environments.

Currently only IPv4 is supported.


#BIG FAT WARNING

Firstly, you should be aware that changing your PAM configuration could result in locking yourself out of your own computer systems if you get something wrong or encounter some kind of weird error. 

This PAM module is free software under the Gnu Public Licence version 3,  and comes with no express or implied warranties or guarentees of anything. 



# INSTALL

The usual proceedure:

```
./configure
make
make install
```

should work. The 'make install' stage will have to be done as root. This will copy the pam_ihosts.so file into /lib/security.



# CONFIGURATION

pam_ihosts.so is configured by adding a line to the appropriate file in /etc/pam.d. So, for example, if we wish to add pam_ihosts to the 'sshd' service, we would add the following line to /etc/pam.d/sshd
```
auth    required  pam_ihosts.so user=root file=/etc/10k-common-passwords.txt
```
This specifies that, for user root, we should check for ihosts in the file /etc/10k-common-passwords.txt, which is a cleartext list of commonly used passwords.

Configuration options are:

**user=[user patterns]**  
Comma separated list of fnmatch (shell-style) patterns that identify users for whom this rule applies. To match all users either leave this out, leave it blank, or explicitly set it to 'user=\*'. A '!' character at the start of the pattern allows inversion, so to match all users but root use: 'user=!root'

**syslog**  
Record events via syslog messages

**script=[path]**  
Run script in the event of a DENY. Arguments passed to the script will be 'User', 'IP', 'Mac Address' and 'Region'. 'Region' will be in the format `<registrar>:<countrycode>`, so for example, `ripencc:GB`.

**allow-ip=[ip]**  
**allow-ips=[ip]**  
A comma-separated list of fnmatch patterns that match IP addresses allowed to log in.

**allow-mac=[mac]**  
**allow-macs=[mac]**  
A comma-separated list of fnmatch patterns that match MAC addresses allowed to log in.

**allow-dev=[dev]**  
**allow-devs=[dev]**  
**allow-device=[dev]**  
**allow-devices=[dev]**  
A comma-separated list of fnmatch patterns that match network device names that the connection is coming to. This is the network adapter on your machine that is *receiving* the connection from the remote host.

**allow-region=[region]**  
**allow-regions=[region]**  
A comma-separated list of fnmatch patterns that match region strings looked up in IP registrar files. Region strings are in the format `<registrar>:<countrycode>`. This option requires you to supply the paths to the region files with the 'region-files' option. For more details see 'REGIONS' below.

**region-files=[path]**  
A comma-separated list of paths to files containing IP registrar assignments. For more details see 'REGIONS' below.


# MAC address and device matches

pam_ihosts.so looks up MAC addresses and devices in the /proc/net/arps file. If an IP does not have an entry in this file, then both MAC address and Device will be set to 'remote', as the connecting host is not on the same subnet as the target host.


# REGIONS

Region information is looked up in files provided by the Regional Internet Registries. These files are downloadable at the following addresses:

http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest      # Latin America
http://ftp.ripe.net/ripe/stats/delegated-ripencc-latest             # Europe, Russia, Middle East
http://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest   # North America
http://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest   # Africa
http://ftp.apnic.net/stats/apnic/delegated-apnic-latest             # Asia Pacific


These files contain information about ip-address assignments against country-code. pam_ihosts looks an ip-address up in them, and extracts a string in the form `<registrar>:<countrycode>`, against which it matches the 'allow-region' option. 

A special case are 'private' IP addresses (e.g. 10.x.x.x, 192.168.x.x). These will return the string 'local'.

# EXAMPLES

Allow root login only from 192.168.0.x
```
account    required  pam_ihosts.so user=root syslog allow-ip=192.168.0.*
```

For all users allow login only from two mac-addresses
```
account    required  pam_ihosts.so user=* allow-mac=ff:c0:a8:e4:99:31,ff:c0:a8:f9:cc:01 
```

For all users other than root, allow login only from ip-addresses in Great Britain.
```
account    required  pam_ihosts.so user=!root region-files=/etc/ip-lists/delegated-afrinic-latest,/etc/ip-lists/delegated-lacnic-latest,/etc/ip-lists/delegated-apnic-latest,/etc/ip-lists/delegated-ripencc-latest allow-region=ripencc:GB
```

For all users, allow login only from Asia Pacific IPs.
```
account    required  pam_ihosts.so user=* region-files=/etc/ip-lists/delegated-afrinic-latest,/etc/ip-lists/delegated-lacnic-latest,/etc/ip-lists/delegated-apnic-latest,/etc/ip-lists/delegated-ripencc-latest allow-region=apnic:*
```

Same as above, but perhaps more efficient, only look up regions in the apnic file.
```
account    required  pam_ihosts.so user=* region-files=/etc/ip-lists/delegated-apnic-latest allow-region=apnic:*
```


