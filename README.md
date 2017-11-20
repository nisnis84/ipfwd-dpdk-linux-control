# ipfwd-dpdk-linux-control
Implement IP forwarding in DPDK using Linux networking stack as control plan 

TODOS
-----
1. add dpdk fast path to stats
2. support more than 2 pyshical ports (hard coded for now)
3. dymanic queue number on TX (hard coded queue 1 for TX to ETH)
4. print arp table in application stats
5. handle compilations warnnings


limitations
------------
1. ipv4 support only


user guide
-----------
For example, to run the application with two ports served by 4 lcores, one lcore of RX, one lcore of TX for each port:
 kni -l 12-17 -n 4  -- -P -p 0x3 --config="(0,12,13),(1,15,16)"

