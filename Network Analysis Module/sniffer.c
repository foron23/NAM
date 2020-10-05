/*
   sniffer.c

   Example packet sniffer using the libpcap packet capture library available
   from http://www.tcpdump.org.

   ------------------------------------------

   Copyright (c) 2012 Vic Hargrave

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include "globals.h"
#include "sniffer.h"


#define FLOW_NOT_FOUND 404
#define CIRCBUFSIZE 100





pcap_t* pd;
int linkhdrlen;
struct pcap_stat curr_stats, stats;

int packets;
char interface[256], bpfstr[256];

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    pcap_if_t* interface_list;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;


    pcap_findalldevs(&interface_list, errbuf);

    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = interface_list->name))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }
    free(interface_list);
    // Open the device for live capture, as opposed to reading a packet
    // capture file.
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }

    // Convert the packet filter epxression into a packet
    // filter binary.
    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    return pd;
}

void capture_loop(pcap_t* pd, int packets, pcap_handler func)
{
    int linktype;

    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }

    // Set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;

    case DLT_EN10MB:
        linkhdrlen = 14;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;

    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }

    // Start capturing packets.
    if (pcap_loop(pd, packets, func, 0) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}


void myPacketParser(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
  struct ip* iphdr;

#ifdef DEBUG
  printf("PTR: %p \n ", packetptr);
  fflush(stdout);
  printf("Packet Incoming...\n");
#endif

  packetptr += linkhdrlen;


  uint8_t *packetptr_aux = (uint8_t *)malloc( packethdr->caplen * sizeof(uint8_t));
  memcpy(packetptr_aux,packetptr, packethdr->caplen * sizeof(uint8_t));



  CircBuf_Pkt_push(packetptr_aux);

#ifdef DEBUG
  printf("Packet pushed\n");
#endif
}


void bailout(int signo)
{
    struct pcap_stat stats;


    if (pcap_stats(pd, &stats) >= 0)
    {
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
    }
    pcap_breakloop(pd);
    pcap_close(pd);
    exit(0);
}

int sniffer()
{

    // Open libpcap, set the program termination signals then start
    // processing packets.
    if ((pd = open_pcap_socket(interface, bpfstr)))
    {
        signal(SIGINT, bailout);
        signal(SIGTERM, bailout);
        signal(SIGQUIT, bailout);

        pcap_stats(pd, &stats);
        pcap_stats(pd, &curr_stats);
        capture_loop(pd, packets, (pcap_handler)myPacketParser);

        bailout(0);
    }
    exit(0);
}
