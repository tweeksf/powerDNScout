PowerDNScout
<hr>
Crawls all publicly accessible PowerDNS systems for DNS queries seen by the open resolver. <br>
<br>
- Discovery via Shodan<br>

- https://www.shodan.io/search?query=%22PowerDNS+Authoritative+Server+Monitor%22
<br>
- SOCKS5 capable 
<br>
- Ouputs in ascii or json formats. 
<br>
<br>
Example output:

```
IP: 146.185.199.62
Country: Russian Federation 
Org: EdgeCenter LLC

DNS queries:
Domain: ns2.dnsedgecenter.com, Count: 2822, Query Type: A, AAAA
Domain: ns1.dnsedgecenter.com, Count: 2658, Query Type: A, AAAA, SOA
Domain: ns3.dnsedgecenter.com, Count: 960, Query Type: AAAA
Domain: ns4.dnsedgecenter.com, Count: 425, Query Type: A, AAAA
Domain: ns6.dnsedgecenter.com, Count: 411, Query Type: A, AAAA
Domain: ns5.dnsedgecenter.com, Count: 395, Query Type: A, AAAA
Domain: dnsedgecenter.com, Count: 294, Query Type: NS, DNSKEY, SOA, AAAA, A, MX, TXT
Domain: jd.com, Count: 58, Query Type: A
Domain: direct.shodan.io, Count: 33, Query Type: A
Domain: ip.parrotdns.com, Count: 14, Query Type: A
Domain: dnsscan.shadowserver.org, Count: 13, Query Type: A
Domain: www.google.com, Count: 6, Query Type: A
Domain: www.DNSEdGEcEnteR.com, Count: 6, Query Type: SOA
Domain: aaa.stage.15790461.ns1.1U1gpUP5i8KbTVCTq9PeakbLHhZk.com, Count: 5, Query Type: TXT
Domain: a.root-servers.net, Count: 5, Query Type: A
Domain: ., Count: 4, Query Type: NS
Domain: xn--nameservertest.ripe.net, Count: 4, Query Type: A
Domain: www.baidu.com, Count: 4, Query Type: A
Domain: xn--nameservertest.iis.se, Count: 4, Query Type: A
Domain: xn--nameservertest.icann.org, Count: 4, Query Type: A
Domain: weather.com, Count: 3, Query Type: TXT
Domain: google.com, Count: 3, Query Type: A
Domain: babycenter.com, Count: 2, Query Type: TXT
Domain: cyberresilience.io, Count: 2, Query Type: A
Domain: rr-mirror.research.nawrocki.berlin, Count: 2, Query Type: A
Domain: stackoverflow.com, Count: 2, Query Type: A
Domain: www.wikipedia.org, Count: 2, Query Type: A
Domain: Ns1.dnSedGeCEnTEr.cOm, Count: 2, Query Type: A6
Domain: mail.dnsedgecenter.com, Count: 4, Query Type: AAAA, A
Domain: www.example.com, Count: 2, Query Type: A
Domain: 92b9c73e.asertdnsresearch.com, Count: 2, Query Type: A
Domain: lenovo.com, Count: 2, Query Type: TXT
Domain: gap.com, Count: 2, Query Type: TXT
Domain: ipv6-hitlist.measr.net, Count: 1, Query Type: AAAA
Domain: tstng.net, Count: 1, Query Type: A
Domain: 146.185.199.62.1707735600.main.research.openresolve.rs, Count: 1, Query Type: A
Domain: lanacion.com.ar, Count: 1, Query Type: TXT
Domain: 2461648702.round2024-02-07.odns.m.dnsscan.top, Count: 1, Query Type: A
Domain: c1.146-185-199-62.lahho.ipv4.n64.top, Count: 1, Query Type: TXT
Domain: adriennepeters.eu, Count: 1, Query Type: RRSIG
Domain: a.gtld-servers.net, Count: 1, Query Type: A
Domain: cnnic.cn, Count: 1, Query Type: A
Domain: tmz.com, Count: 1, Query Type: TXT
Domain: ebay.com, Count: 1, Query Type: TXT
Domain: baidu.com, Count: 1, Query Type: A
Domain: dns-test.research.a10protects.com, Count: 1, Query Type: TXT
Domain: b34roq.92b9c73e.n41250.drakkarns.com, Count: 1, Query Type: A
Domain: kohls.com, Count: 1, Query Type: TXT
Domain: realtor.com, Count: 1, Query Type: TXT
Domain: hm.com, Count: 1, Query Type: TXT
Domain: _dns.resolver.arpa, Count: 1, Query Type: SVCB
```
