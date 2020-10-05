#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include "globals.h"
#include "calculation.h"
#include "analyzer.h"


#define FLOW_NOT_FOUND 404

//int debug;
//Funcion de busqueda de flow en el buffer.
//IN: Puntero al buffer circular que se va a usar y el flow que se quiere checkear
//OUT: 2 output previstos:
//    - Indice del elemento que tiene las mismas caracteristicas o las mismas pero en sentido inverso.
//    - Codigo de error 404, un numero que esta out of bounds de [-100, 100] (No me convence esta solucion, pero de momento se quedara asi)
int fetch_flow(flow thisFlow )
{
  int i = 0;
  flow bufElement;

  for(i=0; i< buf.size; i++)
  {
    bufElement = buf.connections[i];
    //buscamos un flow con las mismas caracteristicas ip, puertos y protocolo
    if((strcmp(bufElement.f_srcip,thisFlow.f_srcip) == 0  && strcmp(bufElement.f_dstip,thisFlow.f_dstip) == 0 &&
    bufElement.f_srcPort == thisFlow.f_srcPort && bufElement.f_dstPort == thisFlow.f_dstPort &&
    strcmp(bufElement.protocol,thisFlow.protocol) == 0)
    ||
    (strcmp(bufElement.f_srcip,thisFlow.f_dstip) == 0  && strcmp(bufElement.f_dstip,thisFlow.f_srcip) == 0 &&
    bufElement.f_srcPort == thisFlow.f_dstPort && bufElement.f_dstPort == thisFlow.f_srcPort &&
    strcmp(bufElement.protocol,thisFlow.protocol) == 0))

      {

        return i;
      }

  }

//No hay indice 404, se devuelve como un codigo de error.
  return FLOW_NOT_FOUND;
}


// update de la inf del flow en sentido src->dst
void updateFlow_src(flow newFlow, directional_info extra_info ,int index, struct timespec time)
{
  double elapsed;

   flow ThisFlow = buf.connections[index];
   ThisFlow.data.src_numPackets++;
   ThisFlow.data.src_totalBytes += extra_info.byteCount;
   ThisFlow.data.sttl = extra_info.ttl;
   ThisFlow.data.s_loss += extra_info.loss;
   ThisFlow.data.tcp_window += newFlow.data.tcp_window;
   elapsed = calculate_time(ThisFlow.data.current_tmp_src, time);
   ThisFlow.data.total_arrival_time += elapsed;
   ThisFlow.data.current_tmp = time;
   ThisFlow.data.current_tmp_src = time;
   ThisFlow.data.http_resp_size += newFlow.data.http_resp_size;
   buf.connections[index]= ThisFlow;

}
// update de la inf del flow en sentido dst->src
void updateFlow_dst( flow newFlow,directional_info extra_info, int index, struct timespec time)
{

  flow ThisFlow = buf.connections[index];
  ThisFlow.data.dst_numPackets++;
  ThisFlow.data.dst_totalBytes += extra_info.byteCount;
  ThisFlow.data.dttl = extra_info.ttl;
  ThisFlow.data.current_tmp = time;
  ThisFlow.data.http_resp_size += newFlow.data.http_resp_size;

  buf.connections[index]= ThisFlow;
}


int isReversed(flow thisFlow, flow newFlow)
{
  //Same direction
  if(strcmp(newFlow.f_srcip,thisFlow.f_srcip) == 0 && strcmp(newFlow.f_dstip,thisFlow.f_dstip) == 0 &&
  newFlow.f_srcPort == thisFlow.f_srcPort && newFlow.f_dstPort == thisFlow.f_dstPort &&
  strcmp(newFlow.protocol,thisFlow.protocol) == 0)
  {
    return 0;
  }
  //Reversed direction
  if(strcmp(newFlow.f_srcip,thisFlow.f_dstip) == 0 && strcmp(newFlow.f_dstip,thisFlow.f_srcip) == 0 &&
  newFlow.f_srcPort == thisFlow.f_dstPort && newFlow.f_dstPort == thisFlow.f_srcPort &&
  strcmp(newFlow.protocol,thisFlow.protocol) == 0)
  {
    return 1;
  }
}



int PacketAnalyzer()
{

  struct ip* iphdr;
  struct icmphdr* icmphdr;
  struct tcphdr* tcphdr;
  struct udphdr* udphdr;
  uint8_t *packetptr, *packetptr_aux;

  flow thisFlow;
  directional_info extra_info;
  struct timespec timestamp;
  double medition;

  char iphdrInfo[256], srcip[256], dstip[256];
  unsigned short id, seq;
  int srcPort, dstPort, byteCount;
  short int tcp_win, ind;

  char *data;
  char *contentlen, *pt2;

while(1)
{

#ifdef DEBUG
  printf("Another analyzer round \n");
  printf("Get the packet...\n");
#endif

packetptr = CircBuf_Pkt_pop();
packetptr_aux = packetptr;

#ifdef DEBUG
  printf("Packet popped... %p \n", packetptr);
#endif

// Skip the datalink layer header and get the IP header fields.
clock_gettime(CLOCK_REALTIME,&timestamp);

iphdr = (struct ip*)packetptr;

strcpy(thisFlow.f_srcip, inet_ntoa(iphdr->ip_src));
strcpy(thisFlow.f_dstip, inet_ntoa(iphdr->ip_dst));
thisFlow.data.http_resp_size = 0;
extra_info.byteCount = ntohs(iphdr->ip_len);
extra_info.ttl = iphdr->ip_ttl;

pcap_stats(pd, &stats);
extra_info.loss = (stats.ps_drop - curr_stats.ps_drop) + (stats.ps_ifdrop - curr_stats.ps_ifdrop);
curr_stats = stats;

// Advance to the transport layer header then parse and display
// the fields based on the type of hearder: tcp, udp or icmp.
packetptr += 4*iphdr->ip_hl;
switch (iphdr->ip_p)
{
case IPPROTO_TCP:
    tcphdr = (struct tcphdr*)packetptr;
    thisFlow.f_srcPort = ntohs(tcphdr->source);
    thisFlow.f_dstPort = ntohs(tcphdr->dest);
    thisFlow.protocol = "TCP";
    thisFlow.data.tcp_window = ntohs(tcphdr->window);


    if(thisFlow.f_srcPort == 80)
    {
      data = (char*)(packetptr + sizeof(struct ip) + sizeof(struct tcphdr));
      contentlen = strstr(data, "Content-Length");

      if(contentlen != NULL)
      {
        contentlen += strlen("Content-Length: ");
        pt2 = strstr(contentlen, "\r\n");
        contentlen + (pt2 - contentlen) = '\0';
        int data_length = atoi(contentlen);
        thisFlow.data.http_resp_size = data_length;
      }

      ///////////// PRUEBAS PARA HTTP A SECAS ///////////////
      //https://www.mixedcontentexamples.com/
    }

    break;

case IPPROTO_UDP:
    udphdr = (struct udphdr*)packetptr;
    thisFlow.f_srcPort = ntohs(udphdr->source);
    thisFlow.f_dstPort = ntohs(udphdr->dest);
    thisFlow.protocol = "UDP";


    break;

case IPPROTO_ICMP:
    icmphdr = (struct icmphdr*)packetptr;
    thisFlow.protocol = "ICMP";

    break;
}
ind = fetch_flow( thisFlow);

if(ind==FLOW_NOT_FOUND)
{
  id =  CircBuf_Flow_push(thisFlow, extra_info, timestamp);


  #ifdef DEBUG
    printf("Flow pushed.\n" );
  #endif

}
else
{
  #ifdef DEBUG
    printf("fetched %d\n", ind);
  #endif

  if(isReversed(buf.connections[ind], thisFlow))
  {


    updateFlow_dst( thisFlow,  extra_info ,ind, timestamp);
    #ifdef DEBUG
      printf("updated dst->src\n" );
    #endif
  }
  else
  {
    updateFlow_src( thisFlow,  extra_info ,ind, timestamp);
    #ifdef DEBUG
      printf("updated src->dst\n" );
    #endif
  }
}
#ifdef DEBUG
  printf("################## %p \n", packetptr_aux);
#endif
free(packetptr_aux);

printf("Packet processed\n");
}
return 0;
}
