/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include <bits/sockaddr.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>
#include <rte_hash_crc.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_hash.h>


/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD                  128

/* Number of TX ring descriptors */
#define NB_TXD                  512

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400

#define KNI_MAX_KTHREAD 32

#define xstr(s) str(s)
#define str(s) #s

#define ARP_CACHE       "/proc/net/arp"
#define ARP_STRING_LEN  1023
#define ARP_BUFFER_LEN  (ARP_STRING_LEN + 1)

/* Format for fscanf() to read the 1st (IP address), 4th (MAC address), and 6th (Interface) space-delimited fields */
#define ARP_LINE_FORMAT "%" xstr(ARP_STRING_LEN) "s %*s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s %*s " \
                        "%" xstr(ARP_STRING_LEN) "s"

#define DEFAULT_HASH_FUNC       rte_hash_crc

#define L3FWD_HASH_ENTRIES 64

#define NB_SOCKETS 4

#define IPV4_L3FWD_EM_NUM_ROUTES 10

struct ipv4_key {
        uint32_t ip_dst;
} __attribute__((__packed__));

struct ipv4_value {
        uint32_t inet_indx;
        uint8_t  hw_address[6];
}  __attribute__((__packed__));



struct ipv4_l3fwd_em_route {
        struct ipv4_key key;
        struct ipv4_value val;
};


static struct ipv4_l3fwd_em_route ipv4_l3fwd_em_route_array[] = {
        {{IPv4(101, 0, 0, 0)}, {0,0}},
        {{IPv4(201, 0, 0, 0)}, {0,0}},
        {{IPv4(204, 0, 0, 0)}, {0,0}},
        {{IPv4(205, 0, 0, 0)}, {0,0}},
        {{IPv4(206, 0, 0, 0)}, {0,0}},
        {{IPv4(207, 0, 0, 0)}, {0,0}},
        {{IPv4(208, 0, 0, 0)}, {0,0}},
        {{IPv4(209, 0, 0, 0)}, {0,0}},
        {{IPv4(211, 0, 0, 0)}, {0,0}},
        {{IPv4(212, 0, 0, 0)}, {0,0}},
};

static struct ipv4_value ipv4_l3fwd_val[L3FWD_HASH_ENTRIES] __rte_cache_aligned;

struct rte_hash *ipv4_l3fwd_em_lookup_struct[20];



/*
 * Structure of port parameters
 */
struct kni_port_params {
        uint8_t port_id;/* Port ID */
        unsigned lcore_rx; /* lcore ID for RX */
        unsigned lcore_tx; /* lcore ID for TX */
        uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
        uint32_t nb_kni; /* Number of KNI devices to be created */
        unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
        struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
} __rte_cache_aligned;

static struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];


/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
        .rxmode = {
                .header_split = 0,      /* Header Split disabled */
                .hw_ip_checksum = 0,    /* IP checksum offload disabled */
                .hw_vlan_filter = 0,    /* VLAN filtering disabled */
                .jumbo_frame = 0,       /* Jumbo Frame Support disabled */
                .hw_strip_crc = 1,      /* CRC stripped by hardware */
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
        },
};

/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;

/* Mask of enabled ports */
static uint32_t ports_mask = 0;
/* Ports set in promiscuous mode off by default. */
static int promiscuous_on = 0;

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
        /* number of pkts received from NIC, and sent to KNI */
        uint64_t rx_packets;

        /* number of pkts received from NIC, but failed to send to KNI */
        uint64_t rx_dropped;

        /* number of pkts received from KNI, and sent to NIC */
        uint64_t tx_packets;

        /* number of pkts received from KNI, but failed to send to NIC */
        uint64_t tx_dropped;
};

/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
static int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);

/* Print out statistics on packets handled */
static void
print_stats(void)
{
        uint8_t i;

        printf("\n**KNI example application statistics**\n"
               "======  ==============  ============  ============  ============  ============\n"
               " Port    Lcore(RX/TX)    rx_packets    rx_dropped    tx_packets    tx_dropped\n"
               "------  --------------  ------------  ------------  ------------  ------------\n");
        for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
                if (!kni_port_params_array[i])
                        continue;

                printf("%7d %10u/%2u %13"PRIu64" %13"PRIu64" %13"PRIu64" "
                                                        "%13"PRIu64"\n", i,
                                        kni_port_params_array[i]->lcore_rx,
                                        kni_port_params_array[i]->lcore_tx,
                                                kni_stats[i].rx_packets,
                                                kni_stats[i].rx_dropped,
                                                kni_stats[i].tx_packets,
                                                kni_stats[i].tx_dropped);
        }
        printf("======  ==============  ============  ============  ============  ============\n");
}

/* Custom handling of signals to handle stats and kni processing */
static void
signal_handler(int signum)
{
        /* When we receive a USR1 signal, print stats */
        if (signum == SIGUSR1) {
                print_stats();
        }

        /* When we receive a USR2 signal, reset stats */
        if (signum == SIGUSR2) {
                memset(&kni_stats, 0, sizeof(kni_stats));
                printf("\n**Statistics have been reset**\n");
                return;
        }

        /* When we receive a RTMIN or SIGINT signal, stop kni processing */
        if (signum == SIGRTMIN || signum == SIGINT){
                printf("SIGRTMIN is received, and the KNI processing is "
                                                        "going to stop\n");
                rte_atomic32_inc(&kni_stop);
                return;
        }
}

static void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
        unsigned i;

        if (pkts == NULL)
                return;

        for (i = 0; i < num; i++) {
                rte_pktmbuf_free(pkts[i]);
                pkts[i] = NULL;
        }
}

static inline uint32_t
ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
                uint32_t init_val)
{
        const struct ipv4_key *k;

        k = data;

        init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
        return init_val;
}

#define BYTE_VALUE_MAX 256
#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

static inline void
populate_ipv4_few_flow_into_table(const struct rte_hash *h)
{
        uint32_t i = 0;
        int32_t ret = 0;
        uint32_t ip_dst_key;

        for (i = 0; i < IPV4_L3FWD_EM_NUM_ROUTES; i++) {
                struct ipv4_l3fwd_em_route  entry;

                entry = ipv4_l3fwd_em_route_array[i];
                ip_dst_key = rte_cpu_to_be_32(entry.key.ip_dst);
                ret = rte_hash_add_key(h, (void *) &ip_dst_key);
                if (ret < 0) {
                        rte_exit(EXIT_FAILURE, "Unable to add entry %" PRIu32
                                " to the l3fwd hash.\n", i);
                }
                ipv4_l3fwd_val[ret] = entry.val;
        }
        printf("Hash: Adding 0x%" PRIx64 " keys\n",
                (uint64_t)IPV4_L3FWD_EM_NUM_ROUTES);
}



/* Return ipv4/ipv6 em fwd lookup struct. */
void *
em_get_ipv4_l3fwd_lookup_struct(const int coreid)
{
        return ipv4_l3fwd_em_lookup_struct[coreid];
}




int init_hash_table(const int socketid)
{
        struct rte_hash_parameters ipv4_l3fwd_hash_params = {
                .name = NULL,
                .entries = L3FWD_HASH_ENTRIES,
                .key_len = sizeof(struct ipv4_key),
                .hash_func = ipv4_hash_crc,
                .hash_func_init_val = 0,
        };

        char s[64] = {0};

        /* create ipv4 hash */
        snprintf(s, sizeof(s), "ipv4_l3fwd_hash_%d", rte_lcore_id());
        ipv4_l3fwd_hash_params.name = s;
        ipv4_l3fwd_hash_params.socket_id = socketid;
        ipv4_l3fwd_em_lookup_struct[rte_lcore_id()] =
                rte_hash_create(&ipv4_l3fwd_hash_params);
        if (ipv4_l3fwd_em_lookup_struct[rte_lcore_id()] == NULL)
                rte_exit(EXIT_FAILURE,
                        "Unable to create the l3fwd hash on socket %d\n",
                        socketid);
        
        /* populate the ipv4 hash */
        populate_ipv4_few_flow_into_table(
                                    ipv4_l3fwd_em_lookup_struct[rte_lcore_id()]);
        

        return 0;
}



int fill_kernel_arp_to_hash();
int fill_kernel_arp_to_hash()
{
    FILE *arpCache = fopen(ARP_CACHE, "r");
    uint8_t hw_addr_byte[6];
    int values[6];
    int indx = 0;
    int i = 0;

    if (!arpCache)
    {
        perror("Arp Cache: Failed to open file \"" ARP_CACHE "\"");
        return 1;
    }

    /* Ignore the first line, which contains the header */
    char header[ARP_BUFFER_LEN];
    if (!fgets(header, sizeof(header), arpCache))
    {
        return 1;
    }

    /* zero the data array */
    bzero(ipv4_l3fwd_em_route_array,sizeof(ipv4_l3fwd_em_route_array));
    /*init hash table as we fill it again */
    rte_hash_reset(ipv4_l3fwd_em_lookup_struct[rte_lcore_id()]);            

    char ipAddr[ARP_BUFFER_LEN], hwAddr[ARP_BUFFER_LEN], device[ARP_BUFFER_LEN];
    int count = 0;
    while (3 == fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, hwAddr, device))
    {
        //printf("%03d: Mac Address of [%s] on [%s] is \"%s\"\n",
            //    ++count, ipAddr, device, hwAddr);
        
        /* add the dest ip as key*/
        int ipbytes[4];
        sscanf(ipAddr, "%d.%d.%d.%d", &ipbytes[0], &ipbytes[1], &ipbytes[2], &ipbytes[3]);
        ipv4_l3fwd_em_route_array[indx].key.ip_dst = IPv4(ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3]);

        //fprintf(stderr, "\nip added is %d\n", ipv4_l3fwd_em_route_array[indx].key.ip_dst);

        /* convert mac string to byte order */
        if( 6 == sscanf( hwAddr, "%x:%x:%x:%x:%x:%x%c",
            &values[0], &values[1], &values[2],
            &values[3], &values[4], &values[5] ) )
        {
              /* convert to uint8_t */
              for( i = 0; i < 6; ++i )
              {
                  ipv4_l3fwd_em_route_array[indx].val.hw_address[i] = (uint8_t) values[i];
              }
        }
        //fprintf(stderr, "\n ether dmac=%02x%02x%02x%02x%02x%02x\n", ipv4_l3fwd_em_route_array[indx].val.hw_address[0], ipv4_l3fwd_em_route_array[indx].val.hw_address[1], ipv4_l3fwd_em_route_array[indx].val.hw_address[2], ipv4_l3fwd_em_route_array[indx].val.hw_address [3], ipv4_l3fwd_em_route_array[indx].val.hw_address[4], ipv4_l3fwd_em_route_array[indx].val.hw_address[5]);

        /* convert the interface to physical port id*/
        if(strncmp(device, "vEth0", 5) == 0)
        {
            ipv4_l3fwd_em_route_array[indx].val.inet_indx = 0;

        }else if (strncmp(device, "vEth1", 5) == 0)
        {
            ipv4_l3fwd_em_route_array[indx].val.inet_indx = 1;

        }
        //fprintf(stderr, "\neth added is %d\n", ipv4_l3fwd_em_route_array[indx].val.inet_indx);
        indx++;
        
    }
   

     /* populate the ipv4 hash */
        populate_ipv4_few_flow_into_table(
                                    ipv4_l3fwd_em_lookup_struct[rte_lcore_id()]);
 
    fclose(arpCache);
    return 0;
    
}

int ip_local_lookup_and_modify_packet(struct rte_mbuf *m, uint8_t* portid)
{
    
        struct ether_hdr *eth_hdr;
        struct ipv4_hdr *ipv4_hdr;
        uint8_t dst_port;
        uint32_t tcp_or_udp;
        uint32_t l3_ptypes;
        int32_t ret = 0;
        uint16_t ether_type;

        eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
        ether_type = eth_hdr->ether_type;
        
        if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) 
        { 
             /* Handle IPv4 headers.*/
             ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
                                                   sizeof(struct ether_hdr));

             /* Find value in hash */
             ret = rte_hash_lookup(em_get_ipv4_l3fwd_lookup_struct(rte_lcore_id()), (const void *)&ipv4_hdr->dst_addr);
             if ((ret != -ENOENT) && (ret != -EINVAL))
             {
                 *portid = ipv4_l3fwd_val[ret].inet_indx; 
             
                  /* Update time to live and header checksum */
                  --(ipv4_hdr->time_to_live);
                  ++(ipv4_hdr->hdr_checksum);

    //              fprintf(stderr, "\n ether dmac=%02x%02x%02x%02x%02x%02x\n", eth_hdr->d_addr.addr_bytes[0], eth_hdr->d_addr.addr_bytes[1], eth_hdr->d_addr.addr_bytes[2], eth_hdr->d_addr.addr_bytes [3], eth_hdr->d_addr.addr_bytes[4], eth_hdr->d_addr.addr_bytes[5]);
                  /* update dst HW addr */
          
                  eth_hdr->d_addr.addr_bytes[0] = ipv4_l3fwd_val[ret].hw_address[0];
                  eth_hdr->d_addr.addr_bytes[1] = ipv4_l3fwd_val[ret].hw_address[1];
                  eth_hdr->d_addr.addr_bytes[2] = ipv4_l3fwd_val[ret].hw_address[2];
                  eth_hdr->d_addr.addr_bytes[3] = ipv4_l3fwd_val[ret].hw_address[3];
                  eth_hdr->d_addr.addr_bytes[4] = ipv4_l3fwd_val[ret].hw_address[4];
                  eth_hdr->d_addr.addr_bytes[5] = ipv4_l3fwd_val[ret].hw_address[5];
                  
      //            fprintf(stderr, "\n changed to=%02x%02x%02x%02x%02x%02x\n", ipv4_l3fwd_val[ret].hw_address[0], ipv4_l3fwd_val[ret].hw_address[1], ipv4_l3fwd_val[ret].hw_address[2], ipv4_l3fwd_val[ret].hw_address [3], ipv4_l3fwd_val[ret].hw_address[4], ipv4_l3fwd_val[ret].hw_address[5]);
                  

                 return 0;
             }else
             {
                fprintf(stderr, "\ndidnt find entry in local hash for ip %u\n", ipv4_hdr->dst_addr);
                return 1;
             }
                 
         } 
         /* packet is not ip packet. return 2 to send to kernel stack */
         return 2;

}

int ip_kernel_fetch()
{

   return 0;

}


/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static void
kni_ingress(struct kni_port_params *p)
{
        uint8_t i, port_id;
        unsigned nb_rx, num;
        uint32_t nb_kni;
        struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
        uint8_t inet_out = 0;
        struct rte_mbuf *tx_pkts_burst_eth[2][PKT_BURST_SZ];
        struct rte_mbuf *tx_pkts_burst_kni[PKT_BURST_SZ];
        int free_indx_eth[2] = {0,0};
        int free_indx_kni = 0;
        unsigned nb_tx = 0;
        int pkts = 0;


        if (p == NULL)
           return;

        nb_kni = p->nb_kni;
        port_id = p->port_id;
        for (i = 0; i < nb_kni; i++) {
                /* Burst rx from eth */
                nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
                if (unlikely(nb_rx > PKT_BURST_SZ)) {
                        RTE_LOG(ERR, APP, "Error receiving from eth\n");
                        return;
                }

                free_indx_eth[0] = 0;
                free_indx_eth[1] = 0;
                free_indx_kni = 0;
                /* for each packet we need to do classification */
                for(pkts = 0; pkts < nb_rx; pkts++)
                {
                      /* search for packet dest IP in local hash table first */
                      int res = ip_local_lookup_and_modify_packet(pkts_burst[pkts], &inet_out);
                      if (res == 0)
                      {
                          /* update mbuf stuct so we will be able to send in a burst*/
                          tx_pkts_burst_eth[inet_out][free_indx_eth[inet_out]++] = pkts_burst[pkts];
                      } else if ((res == 1) && fill_kernel_arp_to_hash() == 0)
                      {
                           /* fetch from linux arp table and search local hash again */
                           if (ip_local_lookup_and_modify_packet(pkts_burst[pkts], &inet_out) == 0)
                           {
                               tx_pkts_burst_eth[inet_out][free_indx_eth[inet_out]++] = pkts_burst[pkts];

                           } else
                           {
                              //no luck, update kni mbuf struct and let linux handle it!
                              tx_pkts_burst_kni[free_indx_kni++] = pkts_burst[pkts];
                           }
                      } else 
                      {
                          //it may be a non ipv4 packet or something went wrong with kernel fetch for arp entry, linux will handle
                          tx_pkts_burst_kni[free_indx_kni++] = pkts_burst[pkts];
                      }
                }
                /* send packets we have route to NIC */
                /* Burst tx to eth */
                nb_tx = rte_eth_tx_burst(0, 1, tx_pkts_burst_eth[0], free_indx_eth[0]);
                if (unlikely(nb_tx < free_indx_eth[0])) {
                       /* Free mbufs not tx to NIC */
                       kni_burst_free_mbufs(&tx_pkts_burst_eth[0][nb_tx], free_indx_eth[0] - nb_tx);
                }

                nb_tx = rte_eth_tx_burst(1, 1, tx_pkts_burst_eth[1], free_indx_eth[1]);
                if (unlikely(nb_tx < free_indx_eth[1])) {
                        /* Free mbufs not tx to NIC */
                        kni_burst_free_mbufs(&tx_pkts_burst_eth[1][nb_tx], free_indx_eth[1] - nb_tx);
                } 
                   
                /* handle dest ip not there in local/kernel tables, send it to kernel stack */
                /* Burst tx to kni */
                num = rte_kni_tx_burst(p->kni[i], tx_pkts_burst_kni, free_indx_kni);
                kni_stats[port_id].rx_packets += num;

                rte_kni_handle_request(p->kni[i]);
                if (unlikely(num < free_indx_kni)) {
                        /* Free mbufs not tx to kni interface */
                        kni_burst_free_mbufs(&pkts_burst[num], free_indx_kni - num);
                        kni_stats[port_id].rx_dropped += free_indx_kni - num;
                }
        }
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static void
kni_egress(struct kni_port_params *p)
{
        uint8_t i, port_id;
        unsigned nb_tx, num;
        uint32_t nb_kni;
        struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

        if (p == NULL)
                return;

        nb_kni = p->nb_kni;
        port_id = p->port_id;
        for (i = 0; i < nb_kni; i++) {
                /* Burst rx from kni */
                num = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
                if (unlikely(num > PKT_BURST_SZ)) {
                        RTE_LOG(ERR, APP, "Error receiving from KNI\n");
                        return;
                }
                /* Burst tx to eth */
                nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t)num);
                kni_stats[port_id].tx_packets += nb_tx;
                if (unlikely(nb_tx < num)) {
                        /* Free mbufs not tx to NIC */
                        kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
                        kni_stats[port_id].tx_dropped += num - nb_tx;
                }
        }
}

static int
main_loop(__rte_unused void *arg)
{
        uint8_t i, nb_ports = rte_eth_dev_count();
        int32_t f_stop;
        const unsigned lcore_id = rte_lcore_id();
        enum lcore_rxtx {
                LCORE_NONE,
                LCORE_RX,
                LCORE_TX,
                LCORE_MAX
        };
        enum lcore_rxtx flag = LCORE_NONE;


        for (i = 0; i < nb_ports; i++) {
                if (!kni_port_params_array[i])
                        continue;
                if (kni_port_params_array[i]->lcore_rx == (uint8_t)lcore_id) {
                        flag = LCORE_RX;
                        /* create hash table for holding route information - only rx cores will use it*/
                        init_hash_table(rte_socket_id());
                        break;
                } else if (kni_port_params_array[i]->lcore_tx ==
                                                (uint8_t)lcore_id) {
                        flag = LCORE_TX;
                        break;
                }
        }

        if (flag == LCORE_RX) {
                RTE_LOG(INFO, APP, "Lcore %u is reading from port %d\n",
                                        kni_port_params_array[i]->lcore_rx,
                                        kni_port_params_array[i]->port_id);
                while (1) {
                        f_stop = rte_atomic32_read(&kni_stop);
                        if (f_stop)
                                break;
                        kni_ingress(kni_port_params_array[i]);
                }
        } else if (flag == LCORE_TX) {
                RTE_LOG(INFO, APP, "Lcore %u is writing to port %d\n",
                                        kni_port_params_array[i]->lcore_tx,
                                        kni_port_params_array[i]->port_id);
                while (1) {
                        f_stop = rte_atomic32_read(&kni_stop);
                        if (f_stop)
                                break;
                        kni_egress(kni_port_params_array[i]);
                }
        } else
                RTE_LOG(INFO, APP, "Lcore %u has nothing to do\n", lcore_id);

        return 0;
}

/* Display usage instructions */
static void
print_usage(const char *prgname)
{
        RTE_LOG(INFO, APP, "\nUsage: %s [EAL options] -- -p PORTMASK -P "
                   "[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
                   "[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
                   "    -p PORTMASK: hex bitmask of ports to use\n"
                   "    -P : enable promiscuous mode\n"
                   "    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
                   "port and lcore configurations\n",
                   prgname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint32_t
parse_unsigned(const char *portmask)
{
        char *end = NULL;
        unsigned long num;

        num = strtoul(portmask, &end, 16);
        if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
                return 0;

        return (uint32_t)num;
}

static void
print_config(void)
{
        uint32_t i, j;
        struct kni_port_params **p = kni_port_params_array;

        for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
                if (!p[i])
                        continue;
                RTE_LOG(DEBUG, APP, "Port ID: %d\n", p[i]->port_id);
                RTE_LOG(DEBUG, APP, "Rx lcore ID: %u, Tx lcore ID: %u\n",
                                        p[i]->lcore_rx, p[i]->lcore_tx);
                for (j = 0; j < p[i]->nb_lcore_k; j++)
                        RTE_LOG(DEBUG, APP, "Kernel thread lcore ID: %u\n",
                                                        p[i]->lcore_k[j]);
        }
}

static int
parse_config(const char *arg)
{
        const char *p, *p0 = arg;
        char s[256], *end;
        unsigned size;
        enum fieldnames {
                FLD_PORT = 0,
                FLD_LCORE_RX,
                FLD_LCORE_TX,
                _NUM_FLD = KNI_MAX_KTHREAD + 3,
        };
        int i, j, nb_token;
        char *str_fld[_NUM_FLD];
        unsigned long int_fld[_NUM_FLD];
        uint8_t port_id, nb_kni_port_params = 0;

        memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
        while (((p = strchr(p0, '(')) != NULL) &&
                nb_kni_port_params < RTE_MAX_ETHPORTS) {
                p++;
                if ((p0 = strchr(p, ')')) == NULL)
                        goto fail;
                size = p0 - p;
                if (size >= sizeof(s)) {
                        printf("Invalid config parameters\n");
                        goto fail;
                }
                snprintf(s, sizeof(s), "%.*s", size, p);
                nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
                if (nb_token <= FLD_LCORE_TX) {
                        printf("Invalid config parameters\n");
                        goto fail;
                }
                for (i = 0; i < nb_token; i++) {
                        errno = 0;
                        int_fld[i] = strtoul(str_fld[i], &end, 0);
                        if (errno != 0 || end == str_fld[i]) {
                                printf("Invalid config parameters\n");
                                goto fail;
                        }
                }

                i = 0;
                port_id = (uint8_t)int_fld[i++];
                if (port_id >= RTE_MAX_ETHPORTS) {
                        printf("Port ID %d could not exceed the maximum %d\n",
                                                port_id, RTE_MAX_ETHPORTS);
                        goto fail;
                }
                if (kni_port_params_array[port_id]) {
                        printf("Port %d has been configured\n", port_id);
                        goto fail;
                }
                kni_port_params_array[port_id] =
                        rte_zmalloc("KNI_port_params",
                                    sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
                kni_port_params_array[port_id]->port_id = port_id;
                kni_port_params_array[port_id]->lcore_rx =
                                        (uint8_t)int_fld[i++];
                kni_port_params_array[port_id]->lcore_tx =
                                        (uint8_t)int_fld[i++];
                if (kni_port_params_array[port_id]->lcore_rx >= RTE_MAX_LCORE ||
                kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
                        printf("lcore_rx %u or lcore_tx %u ID could not "
                                                "exceed the maximum %u\n",
                                kni_port_params_array[port_id]->lcore_rx,
                                kni_port_params_array[port_id]->lcore_tx,
                                                (unsigned)RTE_MAX_LCORE);
                        goto fail;
                }
                for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
                        kni_port_params_array[port_id]->lcore_k[j] =
                                                (uint8_t)int_fld[i];
                kni_port_params_array[port_id]->nb_lcore_k = j;
        }
        print_config();

        return 0;

fail:
        for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
                if (kni_port_params_array[i]) {
                        rte_free(kni_port_params_array[i]);
                        kni_port_params_array[i] = NULL;
                }
        }

        return -1;
}

static int
validate_parameters(uint32_t portmask)
{
        uint32_t i;

        if (!portmask) {
                printf("No port configured in port mask\n");
                return -1;
        }

        for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
                if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
                        (!(portmask & (1 << i)) && kni_port_params_array[i]))
                        rte_exit(EXIT_FAILURE, "portmask is not consistent "
                                "to port ids specified in --config\n");

                if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
                        (unsigned)(kni_port_params_array[i]->lcore_rx)))
                        rte_exit(EXIT_FAILURE, "lcore id %u for "
                                        "port %d receiving not enabled\n",
                                        kni_port_params_array[i]->lcore_rx,
                                        kni_port_params_array[i]->port_id);

                if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
                        (unsigned)(kni_port_params_array[i]->lcore_tx)))
                        rte_exit(EXIT_FAILURE, "lcore id %u for "
                                        "port %d transmitting not enabled\n",
                                        kni_port_params_array[i]->lcore_tx,
                                        kni_port_params_array[i]->port_id);

        }

        return 0;
}

#define CMDLINE_OPT_CONFIG  "config"

/* Parse the arguments given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
        int opt, longindex, ret = 0;
        const char *prgname = argv[0];
        static struct option longopts[] = {
                {CMDLINE_OPT_CONFIG, required_argument, NULL, 0},
                {NULL, 0, NULL, 0}
        };

        /* Disable printing messages within getopt() */
        opterr = 0;

        /* Parse command line */
        while ((opt = getopt_long(argc, argv, "p:P", longopts,
                                                &longindex)) != EOF) {
                switch (opt) {
                case 'p':
                        ports_mask = parse_unsigned(optarg);
                        break;
                case 'P':
                        promiscuous_on = 1;
                        break;
                case 0:
                        if (!strncmp(longopts[longindex].name,
                                     CMDLINE_OPT_CONFIG,
                                     sizeof(CMDLINE_OPT_CONFIG))) {
                                ret = parse_config(optarg);
                                if (ret) {
                                        printf("Invalid config\n");
                                        print_usage(prgname);
                                        return -1;
                                }
                        }
                        break;
                default:
                        print_usage(prgname);
                        rte_exit(EXIT_FAILURE, "Invalid option specified\n");
                }
        }

        /* Check that options were parsed ok */
        if (validate_parameters(ports_mask) < 0) {
                print_usage(prgname);
                rte_exit(EXIT_FAILURE, "Invalid parameters\n");
        }

        return ret;
}

/* Initialize KNI subsystem */
static void
init_kni(void)
{
        unsigned int num_of_kni_ports = 0, i;
        struct kni_port_params **params = kni_port_params_array;

        /* Calculate the maximum number of KNI interfaces that will be used */
        for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
                if (kni_port_params_array[i]) {
                        num_of_kni_ports += (params[i]->nb_lcore_k ?
                                params[i]->nb_lcore_k : 1);
                }
        }

        /* Invoke rte KNI init to preallocate the ports */
        rte_kni_init(num_of_kni_ports);
}

/* Initialise a single port on an Ethernet device */
static void
init_port(uint8_t port)
{
        int ret;

        /* Initialise device and RX/TX queues */
        RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
        fflush(stdout);
        ret = rte_eth_dev_configure(port, 1, 2, &port_conf);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
                            (unsigned)port, ret);

        ret = rte_eth_rx_queue_setup(port, 0, NB_RXD,
                rte_eth_dev_socket_id(port), NULL, pktmbuf_pool);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
                                "port%u (%d)\n", (unsigned)port, ret);

        ret = rte_eth_tx_queue_setup(port, 0, NB_TXD,
                rte_eth_dev_socket_id(port), NULL);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
                                "port%u (%d)\n", (unsigned)port, ret);


        ret = rte_eth_tx_queue_setup(port, 1, NB_TXD,
                rte_eth_dev_socket_id(port), NULL);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
                                "port%u (%d)\n", (unsigned)port, ret);

        ret = rte_eth_dev_start(port);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
                                                (unsigned)port, ret);

        if (promiscuous_on)
                rte_eth_promiscuous_enable(port);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
        uint8_t portid, count, all_ports_up, print_flag = 0;
        struct rte_eth_link link;

        printf("\nChecking link status\n");
        fflush(stdout);
        for (count = 0; count <= MAX_CHECK_TIME; count++) {
                all_ports_up = 1;
                for (portid = 0; portid < port_num; portid++) {
                        if ((port_mask & (1 << portid)) == 0)
                                continue;
                        memset(&link, 0, sizeof(link));
                        rte_eth_link_get_nowait(portid, &link);
                        /* print link status if flag set */
                        if (print_flag == 1) {
                                if (link.link_status)
                                        printf("Port %d Link Up - speed %u "
                                                "Mbps - %s\n", (uint8_t)portid,
                                                (unsigned)link.link_speed,
                                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                                        ("full-duplex") : ("half-duplex\n"));
                                else
                                        printf("Port %d Link Down\n",
                                                (uint8_t)portid);
                                continue;
                        }
                        /* clear all_ports_up flag if any link down */
                        if (link.link_status == ETH_LINK_DOWN) {
                                all_ports_up = 0;
                                break;
                        }
                }
                /* after finally printing all link status, get out */
                if (print_flag == 1)
                        break;

                if (all_ports_up == 0) {
                        printf(".");
                        fflush(stdout);
                        rte_delay_ms(CHECK_INTERVAL);
                }

                /* set the print_flag if all ports up or timeout */
                if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
                        print_flag = 1;
                        printf("done\n");
                }
        }
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
        int ret;
        struct rte_eth_conf conf;

        if (port_id >= rte_eth_dev_count()) {
                RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
                return -EINVAL;
        }

        RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

        /* Stop specific port */
        rte_eth_dev_stop(port_id);

        memcpy(&conf, &port_conf, sizeof(conf));
        /* Set new MTU */
        if (new_mtu > ETHER_MAX_LEN)
                conf.rxmode.jumbo_frame = 1;
        else
                conf.rxmode.jumbo_frame = 0;

        /* mtu + length of header + length of FCS = max pkt length */
        conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
                                                        KNI_ENET_FCS_SIZE;
        ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
        if (ret < 0) {
                RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
                return ret;
        }

        /* Restart specific port */
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
                RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
                return ret;
        }

        return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
        int ret = 0;

        if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
                RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
                return -EINVAL;
        }

        RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
                                        port_id, if_up ? "up" : "down");

        if (if_up != 0) { /* Configure network interface up */
                rte_eth_dev_stop(port_id);
                ret = rte_eth_dev_start(port_id);
        } else /* Configure network interface down */
                rte_eth_dev_stop(port_id);

        if (ret < 0)
                RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);

        return ret;
}

static int
kni_alloc(uint8_t port_id)
{
        uint8_t i;
        struct rte_kni *kni;
        struct rte_kni_conf conf;
        struct kni_port_params **params = kni_port_params_array;

        if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
                return -1;

        params[port_id]->nb_kni = params[port_id]->nb_lcore_k ?
                                params[port_id]->nb_lcore_k : 1;

        for (i = 0; i < params[port_id]->nb_kni; i++) {
                /* Clear conf at first */
                memset(&conf, 0, sizeof(conf));
                if (params[port_id]->nb_lcore_k) {
                        snprintf(conf.name, RTE_KNI_NAMESIZE,
                                        "vEth%u_%u", port_id, i);
                        conf.core_id = params[port_id]->lcore_k[i];
                        conf.force_bind = 1;
                } else
                        snprintf(conf.name, RTE_KNI_NAMESIZE,
                                                "vEth%u", port_id);
                conf.group_id = (uint16_t)port_id;
                conf.mbuf_size = MAX_PACKET_SZ;
                /*
                 * The first KNI device associated to a port
                 * is the master, for multiple kernel thread
                 * environment.
                 */
                if (i == 0) {
                        struct rte_kni_ops ops;
                        struct rte_eth_dev_info dev_info;

                        memset(&dev_info, 0, sizeof(dev_info));
                        rte_eth_dev_info_get(port_id, &dev_info);
                        conf.addr = dev_info.pci_dev->addr;
                        conf.id = dev_info.pci_dev->id;

                        memset(&ops, 0, sizeof(ops));
                        ops.port_id = port_id;
                        ops.change_mtu = kni_change_mtu;
                        ops.config_network_if = kni_config_network_interface;

                        kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
                } else
                        kni = rte_kni_alloc(pktmbuf_pool, &conf, NULL);

                if (!kni)
                        rte_exit(EXIT_FAILURE, "Fail to create kni for "
                                                "port: %d\n", port_id);
                params[port_id]->kni[i] = kni;
        }

        return 0;
}

static int
kni_free_kni(uint8_t port_id)
{
        uint8_t i;
        struct kni_port_params **p = kni_port_params_array;

        if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
                return -1;

        for (i = 0; i < p[port_id]->nb_kni; i++) {
                if (rte_kni_release(p[port_id]->kni[i]))
                        printf("Fail to release kni\n");
                p[port_id]->kni[i] = NULL;
        }
        rte_eth_dev_stop(port_id);

        return 0;
}

/* Initialise ports/queues etc. and start main loop on each core */
int
main(int argc, char** argv)
{
        int ret;
        uint8_t nb_sys_ports, port;
        unsigned i;

        /* Associate signal_hanlder function with USR signals */
        signal(SIGUSR1, signal_handler);
        signal(SIGUSR2, signal_handler);
        signal(SIGRTMIN, signal_handler);
        signal(SIGINT, signal_handler);

        /* Initialise EAL */
        ret = rte_eal_init(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
        argc -= ret;
        argv += ret;

        /* Parse application arguments (after the EAL ones) */
        ret = parse_args(argc, argv);
        if (ret < 0)
                rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");

        /* Create the mbuf pool */
        pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
                MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
        if (pktmbuf_pool == NULL) {
                rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
                return -1;
        }

        /* Get number of ports found in scan */
        nb_sys_ports = rte_eth_dev_count();
        if (nb_sys_ports == 0)
                rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

        /* Check if the configured port ID is valid */
        for (i = 0; i < RTE_MAX_ETHPORTS; i++)
                if (kni_port_params_array[i] && i >= nb_sys_ports)
                        rte_exit(EXIT_FAILURE, "Configured invalid "
                                                "port ID %u\n", i);

        /* Initialize KNI subsystem */
        init_kni();

        /* Initialise each port */
        for (port = 0; port < nb_sys_ports; port++) {
                /* Skip ports that are not enabled */
                if (!(ports_mask & (1 << port)))
                        continue;
                init_port(port);

                if (port >= RTE_MAX_ETHPORTS)
                        rte_exit(EXIT_FAILURE, "Can not use more than "
                                "%d ports for kni\n", RTE_MAX_ETHPORTS);

                kni_alloc(port);
        }
        check_all_ports_link_status(nb_sys_ports, ports_mask);

        /* Launch per-lcore function on every lcore */
        rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
        RTE_LCORE_FOREACH_SLAVE(i) {
                if (rte_eal_wait_lcore(i) < 0)
                        return -1;
        }

        /* Release resources */
        for (port = 0; port < nb_sys_ports; port++) {
                if (!(ports_mask & (1 << port)))
                        continue;
                kni_free_kni(port);
        }
#ifdef RTE_LIBRTE_XEN_DOM0
        rte_kni_close();
#endif
        for (i = 0; i < RTE_MAX_ETHPORTS; i++)
                if (kni_port_params_array[i]) {
                        rte_free(kni_port_params_array[i]);
                        kni_port_params_array[i] = NULL;
                }

        return 0;
}
