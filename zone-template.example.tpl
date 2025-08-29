$ORIGIN {{ ZONE }}.
$TTL 21600
@                             21600   IN  SOA         your-primary-dns.com. zonemaster.your.com. 2502011720 7200 3600 1209600 21600

@                                     IN  NS          your-primary-dns.com.
@                                     IN  NS          your-backup-dns.com

{{ PTR_RECORDS }}