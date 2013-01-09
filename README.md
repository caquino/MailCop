# MailCop - Perl POE postfix delegation policy

## MailCop has the following dependencies:
    Config::IniFiles

    Cache::Memcached

    Module::Pluggable::Ordered

    POE

Some plugins are not finished but the code is functional.

You can find the configuration options inside mailcop.ini.

In the daemontools folder you have example control files to run p0f and mailcop under daemontools.

The code was created having greylist as an action and not a filter, so you can from your filter ask for greylist (for example for high false positive rate filters)

Under the folder plugins-available you can find the following plugins:
    ASNGrey.pm - ASN mapping between mx and source ip
    BlackList.pm - Blacklisting
    GeoIP.pm - Geolocation filtering
    HeloCheck.pm - Helo sanity checks
    PTRCheck.pm - Reverse DNS checking
    SPFCheck.pm - SPF filtering
    Whitelist.pm - Whitelisting
    p0f.pm - Passive OS Fingerprint filtering

This code was written in 2006, it still runing on some email system without maintenance.
