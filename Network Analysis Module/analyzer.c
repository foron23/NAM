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
//#include "circularBuffer.h"
//#include "dataStructures.h"
#include "globals.h"
#include "calculation.h"
#include "analyzer.h"


#define FLOW_NOT_FOUND 404


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
    //(bufElement.f_srcip == thisFlow.f_dstip && bufElement.f_dstip == thisFlow.f_srcip &&
    //bufElement.f_srcPort == thisFlow.f_dstPort && bufElement.f_dstPort == thisFlow.f_srcPort &&
    //bufElement.protocol == thisFlow.protocol))
      {
        //Como controlo que un flow esta finalizado o no?

      //Devuelvo el indice del elemento que contiene el flow.
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



//Mi variante del handler para los paquetes PCAP, basado en el original, pero este usa las estructura de datos flow, el buffer circular y directional info.
// Los protocolos de transporte TCP y UDP estan cubiertos, sin embargo, faltaria definir alguna otra estructura para extraer el puerto de cabeceras desconocidas, seguramente.
// En cada ciclo del handler se genera una instancia flow y de informacion direccional, en las que se guardan los datos extraidos de paquete.
//Al final del programa, una vez la informacion se ha extraido, se revisa la informacion extraida y se intenta sumar a un flow, en ausencia de uno, se crea uno nuevo.
//Problemas conocidos:
//  -No se sabe cuando un Flow se da por acabado.
//  -No se como extraer la informacion de tiempo para el packet inter-arrival time y el load
//  -Me falta sacar http response time
//  -No imprime la informacion de ninguna manera
//  -parece absurdamente ineficiente, pierde muchos paquetes y requiere de mucho CPU usage, viendo como suena el ordenador.
//
// TO DO:
//  -Algoritmo para generar las features complejas, de manera similar al printeo
//  -resolver las features de tiempo
//  -crear algun control para el volcado de paquetes, ya sea por tiempo o por cantidad de paquetes.
//  -La integracion con el programa python y tal


int PacketAnalyzer()
{

  struct ip* iphdr;
  struct icmphdr* icmphdr;
  struct tcphdr* tcphdr;
  struct udphdr* udphdr;
  u_char *packetptr;

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
printf("Another analyzer round \n");

printf("Get the packet...\n");
packetptr = CircBuf_Pkt_pop();
printf("Packet popped...\n");

//pcap_stats(pd, &curr_stats);

//printf("sizeof flow %ld\n",sizeof(flow));
//id = -1;

// Skip the datalink layer header and get the IP header fields.
//Hay paquetes
clock_gettime(CLOCK_REALTIME,&timestamp);
//printf("this timestamp, sec: %ld, nsec: %ld \n",timestamp.tv_sec, timestamp.tv_nsec );
//packetptr += linkhdrlen;
iphdr = (struct ip*)packetptr;

printf("Petada 1\n");
//El codigo revienta aqui cuando el el buffer de paquetes no hace pop
strcpy(thisFlow.f_srcip, inet_ntoa(iphdr->ip_src));
strcpy(thisFlow.f_dstip, inet_ntoa(iphdr->ip_dst));
thisFlow.data.http_resp_size = 0;
extra_info.byteCount = ntohs(iphdr->ip_len);
extra_info.ttl = iphdr->ip_ttl;
//printf("Petada 2\n");

//Funciona bien, pero va como por chunks, podria no dar un comportamiento esperado.
    pcap_stats(pd, &stats);
    //printf("%d packets received\n", stats.ps_recv - curr_stats.ps_recv );
    extra_info.loss = (stats.ps_drop - curr_stats.ps_drop) + (stats.ps_ifdrop - curr_stats.ps_ifdrop);
    //printf("%d packets dropped\n\n", stats.ps_drop);
    curr_stats = stats;
//printf("Petada 3\n");

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
    //printf("im a tcp packet\n");


    // thisFlow.f_srcPort == 443 no tiene sentido para ser usado, puesto que las cabeceras tambien van cifradas cuando se detecta el paquete.
    // Damos por hecho que el contenido http interesante se manda desde el servidor, por lo tanto puerto src

    if(thisFlow.f_srcPort == 80)
    {
      data = (char*)(packetptr + sizeof(struct ip) + sizeof(struct tcphdr));
      //printf("%s\n", data );
      contentlen = strstr(data, "Content-Length");

      if(contentlen != NULL)
      {
        contentlen += strlen("Content-Length: ");
        pt2 = strstr(contentlen, "\r\n");
        contentlen + (pt2 - contentlen) = '\0';
        int data_length = atoi(contentlen);
        //printf("%s\n", contentlen );
        //printf("%d\n", data_length);
        thisFlow.data.http_resp_size = data_length;
      }
      //printf("Petada 4\n");

      //sacar el numero de bytes de la respuesta de las cabeceras http
      ///////// Posible idea: https://stackoverflow.com/questions/22077802/simple-c-example-of-doing-an-http-post-and-consuming-the-response
      ///////// https://elf11.github.io/2017/01/22/libpcap-in-C.html

      ///////////// PRUEBAS PARA HTTP A SECAS ///////////////
      //https://www.mixedcontentexamples.com/
    }

    break;

case IPPROTO_UDP:
    udphdr = (struct udphdr*)packetptr;
    thisFlow.f_srcPort = ntohs(udphdr->source);
    thisFlow.f_dstPort = ntohs(udphdr->dest);
    thisFlow.protocol = "UDP";
    //printf("im an udp packet\n");
    //printf("Petada 5\n");

    break;

case IPPROTO_ICMP:
    icmphdr = (struct icmphdr*)packetptr;
    thisFlow.protocol = "ICMP";
    //printf("im an icmp packet\n");

    break;
}
//printf("Gotta fetch\n");
//Tenemos toda la informacion necesaria para mirar los flows.
ind = fetch_flow( thisFlow);
//printf("fetched %d\n", ind);
//printf("Petada 6\n");

//Hay que crear un nuevo flow en el buffer
if(ind==FLOW_NOT_FOUND)
{
  //printf("Pushing a new flow..." );
  id =  CircBuf_Flow_push(thisFlow, extra_info, timestamp);
  printf("Flow pushed.\n" );

}
else  //Ya existe el flow, donde hay que meter la informacion nueva?
{
  printf("fetched %d\n", ind);
  if(isReversed(buf.connections[ind], thisFlow))
  {
    printf(" updating dst->src\n" );
    updateFlow_dst( thisFlow,  extra_info ,ind, timestamp);
    printf(" updated dst->src\n" );

  }
  else
  {
    printf(" updating src->dst\n" );
    updateFlow_src( thisFlow,  extra_info ,ind, timestamp);
    printf(" updated src->dst\n" );

  }
}
//if(ind != FLOW_NOT_FOUND)
  //printf("buf pos %d, code %d\n", id, ind );
printf("Flow %s:%d -> %s:%d, proto: %s \n",thisFlow.f_srcip,thisFlow.f_srcPort,thisFlow.f_dstip,thisFlow.f_dstPort, thisFlow.protocol);
    //if(thisFlow.f_srcPort == 80)
    //  printf("Flow %s:%d -> %s:%d, proto: %s \n",thisFlow.f_srcip,thisFlow.f_srcPort,thisFlow.f_dstip,thisFlow.f_dstPort, thisFlow.protocol);

/*
printf("%d,%d,%d,%d,%f,%f,%d,%f,%d,%f,%f,%d,%d,%d\n",
  buf.connections[tail].data.dst_numPackets, buf.connections[tail].data.src_totalBytes, buf.connections[tail].data.sttl, buf.connections[tail].data.dttl,
  buf.connections[tail].data.s_load, buf.connections[tail].data.d_load, buf.connections[tail].data.s_loss, buf.connections[tail].data.s_inpkt,
  buf.connections[tail].data.tcp_window, buf.connections[tail].data.s_mean, buf.connections[tail].data.d_mean, buf.connections[tail].data.http_resp_size,
  buf.connections[tail].data.same_src_and_dst_ip_ct, buf.connections[tail].data.same_src_ip_and_dst_pt_ct);
*/
printf("Packet processed\n");
}
return 0;
}
