<?php
// Which DNSSEC Resolver do you let Horde query?
$dconf['resolver'] = '127.0.0.1';
// Set the TTL value of CERT RR for use on DNSSEC Authoritative Server.
// DO NOT change the value if you do not know how to use the value.
$dconf['nsupdate']['ttl'] = '300';
// Which DNSSEC Authoritative Server do you want to save the CERT RR?
$dconf['nsupdate']['nameserver'] = 'ns.site1.org';
// The TSIG key is used when Horde will send "nsupdate" command to DNSSEC Authoritative Server
$dconf['nsupdate']['tsigkey'] = '/var/www/dmail/dmailhost.key';
