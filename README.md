# ipfwd-dpdk-linux-control
Implementing basic IP forwarding in DPDK using Linux networking stack as control plan 

The application is making use of DPDK kni and l3fwd sample apps.

BW tests
--------
1. Linux basic IP forwaring feature - 8.5Gbps
2. DPDK kni application  - 5.5Gbps
3. ipwd-dpdk-linux-control application - line rate of 10Gbps

TODOS
-----
1. add dpdk fast path to stats
2. support more than 2 pyshical ports (hard coded for now)
3. dymanic queue number on TX (hard coded queue 1 for TX to ETH)
4. print arp table in application stats


limitations
------------
1. ipv4 support only


Installation
-----------
For example, to run the application with two ports served by 4 lcores (12-15), one lcore of RX, one lcore of TX for each port:

ipfwd -l 12-15 -n 4  -- -P -p 0x3 --config="(0,12,13),(1,14,15)"

