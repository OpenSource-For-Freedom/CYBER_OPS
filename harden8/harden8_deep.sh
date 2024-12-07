############# !! Move to separate section, organize by parts
## of script..... note to self as script gets bigger...this
## alongside other additions/changes to pam, the limits.conf
## and other files in /etc/security will go in this section ##
## Disable core dumps
echo '* hard core 0;' | sudo tee -a /etc/security/limits.conf

## Basic and fundamental hardening via TCP Wrappers
## https://en.wikipedia.org/wiki/TCP_Wrappers

echo "ALL: ALL" | sudo tee -a /etc/hosts.deny
## Disallow non-local logins, this can be kept simple or we can go more in depth

echo "-:ALL:ALL EXCEPT LOCAL" | sudo tee -a /etc/security/access.conf
## What about hosts.deny? What shall I do there?

