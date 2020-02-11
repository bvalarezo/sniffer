CSE363 HW1
Bryan Valarezo
110362410

Sniffer.py | A websniffer used to parse HTTP and TLS traffic using python3 and scapy.

Requirements
  -python3
  -scapy
  
Usage

sniffer.py [-i interface] [-r tracefile] expression

  -i      Read packets from a specific network interface (e.g., eth0) indefinitely. If not
          specified, the program will select the default interface. (Requires root permissions to sniff)

  -r      Read packets from a tracefile.
  
  -h      Prints out the usage information
 
  <expression> a filter expression that specifies a subset of the traffic to be monitored (using BPF format).
  
If neither flag is specified, sniffer.py will sniff packets from a network interface
  
Example output:

Reading packets from interface...
2020-02-11 00:03:55.924103 TLS v1.3 10.0.3.15:57560 -> 172.217.7.4:443 www.google.com
2020-02-11 00:04:22.175044 TLS v1.3 10.0.3.15:48282 -> 23.185.0.2:443 www.cs.stonybrook.edu
2020-02-11 00:04:34.359348 HTTP 10.0.3.15:33174 -> 204.79.197.200:80 www.bing.com GET /
2020-02-11 00:05:34.617293 HTTP 10.0.3.15:40728 -> 130.245.27.3:80 www3.cs.stonybrook.edu GET /~mikepo/CSE363/2020/
2020-02-11 00:05:43.306654 TLS v1.3 10.0.3.15:51734 -> 130.245.27.3:443 www3.cs.stonybrook.edu
2020-02-11 00:11:41.310229 TLS v1.3 10.0.3.15:56964 -> 31.13.71.36:443 www.facebook.com
2020-02-11 00:11:47.676215 TLS v1.3 10.0.3.15:56966 -> 31.13.71.36:443 www.facebook.com
2020-02-11 00:12:52.838636 TLS v1.2 10.0.3.15:45178 -> 172.217.12.174:443 www.youtube.com
2020-02-11 00:13:08.687171 HTTP 10.0.3.15:34512 -> 199.109.99.209:80 detectportal.firefox.com GET /success.txt
2020-02-11 00:13:09.857483 TLS v1.3 10.0.3.15:44014 -> 13.225.230.12:443 snippets.cdn.mozilla.net
2020-02-11 00:13:10.977537 TLS v1.3 10.0.3.15:58114 -> 172.217.10.106:443 safebrowsing.googleapis.com
2020-02-11 00:13:11.017621 HTTP 10.0.3.15:46856 -> 172.217.11.35:80 ocsp.pki.goog POST /gts1o1
2020-02-11 00:13:12.077427 TLS v1.3 10.0.3.15:58950 -> 23.52.164.254:443 img-getpocket.cdn.mozilla.net
2020-02-11 00:13:12.100809 HTTP 10.0.3.15:58892 -> 72.21.91.29:80 ocsp.digicert.com POST /
2020-02-11 00:13:13.487001 TLS v1.3 10.0.3.15:42926 -> 35.165.110.9:443 shavar.services.mozilla.com
2020-02-11 00:13:13.58122 HTTP 10.0.3.15:58896 -> 72.21.91.29:80 ocsp.digicert.com POST /
2020-02-11 00:13:32.64455 TLS v1.0 10.0.3.15:36322 -> 75.2.104.223:443 spacejam.com
2020-02-11 00:13:35.885855 TLS v1.0 10.0.3.15:35412 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:13:36.000122 HTTP 10.0.3.15:34532 -> 199.109.99.209:80 detectportal.firefox.com GET /success.txt
2020-02-11 00:13:42.747408 TLS v1.1 10.0.3.15:35416 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:13:42.858229 HTTP 10.0.3.15:34536 -> 199.109.99.209:80 detectportal.firefox.com GET /success.txt
2020-02-11 00:13:52.408103 TLS v1.2 10.0.3.15:35420 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:13:52.516162 HTTP 10.0.3.15:58910 -> 72.21.91.29:80 ocsp.digicert.com POST /                      
2020-02-11 00:13:52.718755 TLS v1.2 10.0.3.15:34926 -> 104.17.64.4:443 cdnjs.cloudflare.com
2020-02-11 00:13:52.762008 HTTP 10.0.3.15:58910 -> 72.21.91.29:80 ocsp.digicert.com POST /
2020-02-11 00:13:52.800495 TLS v1.2 10.0.3.15:35426 -> 64.41.200.100:443 ssllabs.com
2020-02-11 00:13:52.831431 TLS v1.2 10.0.3.15:35428 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:13:52.833681 TLS v1.2 10.0.3.15:35430 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:13:53.118328 TLS v1.2 10.0.3.15:35432 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:13:53.277756 TLS v1.2 10.0.3.15:60884 -> 172.217.10.136:443 www.googletagmanager.com
2020-02-11 00:13:53.31626 HTTP 10.0.3.15:46892 -> 172.217.11.35:80 ocsp.pki.goog POST /gts1o1
2020-02-11 00:13:53.485825 TLS v1.2 10.0.3.15:53854 -> 172.217.10.238:443 www.google-analytics.com
2020-02-11 00:13:53.636634 TLS v1.2 10.0.3.15:47390 -> 209.85.144.155:443 stats.g.doubleclick.net
2020-02-11 00:13:53.678527 HTTP 10.0.3.15:46892 -> 172.217.11.35:80 ocsp.pki.goog POST /gts1o1
2020-02-11 00:13:53.753918 TLS v1.2 10.0.3.15:57628 -> 172.217.7.4:443 www.google.com
2020-02-11 00:13:53.77819 HTTP 10.0.3.15:46892 -> 172.217.11.35:80 ocsp.pki.goog POST /gts1o1
2020-02-11 00:13:57.1349 TLS v1.2 10.0.3.15:35444 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:13:57.151254 TLS v1.2 10.0.3.15:35446 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:14:11.323364 TLS v1.3 10.0.3.15:58996 -> 23.52.164.254:443 img-getpocket.cdn.mozilla.net
2020-02-11 00:14:13.08643 TLS v1.3 10.0.3.15:35450 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:14:13.114733 TLS v1.3 10.0.3.15:53870 -> 172.217.10.238:443 www.google-analytics.com
2020-02-11 00:14:13.187846 TLS v1.3 10.0.3.15:35452 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:14:13.194304 TLS v1.3 10.0.3.15:35456 -> 64.41.200.100:443 www.ssllabs.com
2020-02-11 00:14:13.254043 TLS v1.3 10.0.3.15:35458 -> 64.41.200.100:443 clienttest.ssllabs.com
2020-02-11 00:14:13.548712 TLS v1.3 10.0.3.15:34964 -> 104.17.64.4:443 cdnjs.cloudflare.com
2020-02-11 00:14:13.978613 TLS v1.3 10.0.3.15:35474 -> 64.41.200.100:443 ssllabs.com
2020-02-11 00:14:14.021576 HTTP 10.0.3.15:51598 -> 64.41.200.100:80 plaintext.ssllabs.com GET /plaintext/1x1-transparent.png?t=1581398053907
2020-02-11 00:14:14.302844 HTTP 10.0.3.15:34614 -> 199.109.99.209:80 detectportal.firefox.com GET /success.txt
2020-02-11 00:14:14.461296 TLS v1.3 10.0.3.15:60948 -> 172.217.10.136:443 www.googletagmanager.com



  
