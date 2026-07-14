# Net-Firewall-BlockerHelper

Helps manage (un)blocking IPs via various firewalls.

Currently included backends are for...

- firewalld
- hosts_deny (TCP wrappers /etc/hosts.deny; libwrap aware daemons only)
- ipfw
- iptables (also supports tarpit/delude targets via xtables-addons)
- nftables
- npf
- pf
- route (null/blackhole routes via iproute2)
- shorewall (dynamic blacklist via shorewall/shorewall6)
- ufw
- xdp (XDP/eBPF packet drops via xdp-filter from xdp-tools)

The following remote/API backends are available. These use LWP::UserAgent,
which is only loaded if they are used.

- cloudflare
- fortigate (Fortinet FortiGate address group via the FortiOS REST API)
- netscaler
- panos (Palo Alto Networks PAN-OS dynamic address group via the User-ID XML API)
- routeros_api (MikroTik RouterOS address-list via the RouterOS 7 REST API)

The following other remote backends are available.

- bgp_rtbh (BGP Remote Triggered Black Hole; announces /32 or /128 routes
  with the RFC 7999 blackhole community, via ExaBGP's exabgpcli or gobgp)
- nsupdate (DNS based blocklist via BIND dynamic updates)
- opnsense (firewall alias via the OPNsense REST API, driven with curl)
- routeros (MikroTik RouterOS address-list, driven over ssh)

The following generic backends are available.

- file_reload (render bans to a file, then run a reload hook)
- shell

And the following example/testing backends are available.

- dummy

```perl
    use Net::Firewall::BlockerHelper;

    # create a instance named ssh with a ipfw backend for port 22 tcp
    my $fw_helper;
    eval {
        $fw_helper = Net::Firewall::BlockerHelper->new(
                backend => 'ipfw',
                ports => ['22'],
                protocols => ['tcp'],
                name => 'ssh',
            );
    };
    if ($@) {
        print 'Error: '
            . $Error::Helper::error
            . "\nError String: "
            . $Error::Helper::errorString
            . "\nError Flag: "
            . $Error::Helper::errorFlag . "\n";
    }

    # start the backend
    $fw_helper->init_backend;

    # ban some IPs
    $fw_helper->ban(ban => '1.2.3.4');
    $fw_helper->ban(ban => '5.6.7.8');

    # unban a IP
    $fw_helper->unban(ban => '1.2.3.4');

    # get a list of banned IPs
    my @banned = $fw_helper->list;
    foreach my $ip (@banned) {
        print 'Banned IP: '.$ip."\n";
    }

    # teardown the backend, re-init, and re-ban everything
    $fw_helper->re_init;

    # teardown the backend
    $fw_helper->teardown;
```

# Install

Rquirements...

- Regexp::IPv4
- Regexp::IPv6
- Error::Helper

To install...

```shell
perl Makefile.PL
make
make test
make install
```

Or via cpanm...

```
cpanm Net::Firewall::BlockerHelper
```
