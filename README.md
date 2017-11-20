# ipfwd-dpdk-linux-control
Implement IP forwarding in DPDK using Linux networking stack as control plan 

TODOS
-----
1. add dpdk fast path to stats
2. support more than 2 pyshical ports (hard coded for now)
3. dymanic queue number on TX (hard coded queue 1 for TX to ETH)
4. print arp table in application stats
5. handle compilations warnnings


limitations:
------------
1. ipv4 support only
