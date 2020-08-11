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

#define FLOW_NOT_FOUND 404
#define CIRCBUFSIZE 100




pcap_t* pd;
int linkhdrlen;

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;

    //pcap_if_t *interface_list;
    //result = pcap_findalldevs(&interface_list,errbuf);


    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }

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

typedef struct directional_info
{
  int byteCount;
  int ttl;
  float time; //Como represento el tiempo??
}directional_info;

typedef struct sample_data
{
  int src_numPackets, dst_numPackets;
  int src_totalBytes, dst_totalBytes;
  int sttl, dttl;
  float s_load, d_load;
  int s_loss;
  int tcp_window;
  float s_inpkt;
  float s_mean, d_mean;
  int http_resp_size;
  int same_src_and_dst_ip_ct;
  int same_src_ip_and_dst_pt_ct;
} sample_data;

typedef struct flow
{
  char f_srcip[256],f_dstip[256];
  unsigned int f_srcPort, f_dstPort;
  char* protocol;
  sample_data data;
} flow;

// Estructura datos buffer circular, aunque es probable que solo use tail, para los push
typedef struct CircBuf
{
  int head;
  int tail;
  int size;
  flow connections[CIRCBUFSIZE];
} CircBuf;

// Inicializacion de buffer circular
void CircBuf_Init(CircBuf buf)
{
  buf.head = 0;
  buf.tail = 0;
  buf.size = CIRCBUFSIZE;
}
int CircBuf_Print(CircBuf buf)
{
    int i=0;
    for(i=0; i< buf.size; i++)
    {
        printf("i=%d, Flow %s:%d -> %s:%d , proto: %s \n"
        ,i, buf.connections[i].f_srcip,buf.connections[i].f_srcPort ,buf.connections[i].f_dstip
        , buf.connections[i].f_dstPort, buf.connections[i].protocol);
    }
    printf("\n");
    return(0);
}
int CircBuf_push(CircBuf buf, flow newFlow, directional_info extra_info)
{
  int last_index= buf.tail++;
  buf.connections[last_index] = newFlow;
  buf.connections[last_index].data.src_numPackets = 1;
  buf.connections[last_index].data.src_totalBytes = extra_info.byteCount;
  buf.connections[last_index].data.sttl = extra_info.ttl;
  //load se deberia calcular al final con totalBytes y alguna variable de tiempo
  buf.connections[last_index].data.tcp_window = newFlow.data.tcp_window;
  //inter arrival sera la variable de tiempo / numpackets
  //mean es totalbytes / numpackets

    if (buf.tail == buf.size)
    {
      buf.tail = 0;
    }
    return buf.tail;
}


int isReversed(flow thisFlow, flow newFlow)
{
  //Same direction
  if(newFlow.f_srcip == thisFlow.f_srcip && newFlow.f_dstip == thisFlow.f_dstip &&
  newFlow.f_srcPort == thisFlow.f_srcPort && newFlow.f_dstPort == thisFlow.f_dstPort &&
  newFlow.protocol == thisFlow.protocol)
  {
    return 0;
  }
  //Reversed direction
  if(newFlow.f_srcip == thisFlow.f_dstip && newFlow.f_dstip == thisFlow.f_srcip &&
  newFlow.f_srcPort == thisFlow.f_dstPort && newFlow.f_dstPort == thisFlow.f_srcPort &&
  newFlow.protocol == thisFlow.protocol)
  {
    return 1;
  }
}

//Funcion de busqueda de flow en el buffer.
//IN: Puntero al buffer circular que se va a usar y el flow que se quiere checkear
//OUT: 2 output previstos:
//    - Indice del elemento que tiene las mismas caracteristicas o las mismas pero en sentido inverso.
//    - Codigo de error 404, un numero que esta out of bounds de [-100, 100] (No me convence esta solucion, pero de momento se quedara asi)
int fetch_flow(CircBuf buf, flow thisFlow )
{
  int i = 0;
  flow bufElement;
  int found = 0;

  while (i < buf.size && !found){
    bufElement = buf.connections[i];
    //buscamos un flow con las mismas caracteristicas ip, puertos y protocolo
    if((bufElement.f_srcip == thisFlow.f_srcip && bufElement.f_dstip == thisFlow.f_dstip &&
    bufElement.f_srcPort == thisFlow.f_srcPort && bufElement.f_dstPort == thisFlow.f_dstPort &&
    bufElement.protocol == thisFlow.protocol)
    ||
    (bufElement.f_srcip == thisFlow.f_dstip && bufElement.f_dstip == thisFlow.f_srcip &&
    bufElement.f_srcPort == thisFlow.f_dstPort && bufElement.f_dstPort == thisFlow.f_srcPort &&
    bufElement.protocol == thisFlow.protocol))
      {
        //Como controlo que un flow esta finalizado o no?
        //Si no se controla podria darse que solo se encuentre la primera ocurrencia
        found = 1;

      //Devuelvo el indice del elemento que contiene el flow.
        return i;
      }

//Relaciones bidireccionales?
//Si el flow es lo mismo pero en sentido contrario el conteo tambien deberia ejecutarse para sumar en las variables de tipo dst.
/*
      if(bufElement.f_srcip == thisFlow.f_dstip && bufElement.f_dstip == thisFlow.f_srcip &&
      bufElement.f_srcPort == thisFlow.f_dstPort && bufElement.f_dstPort == thisFlow.f_srcPort &&
      bufElement.protocol == thisFlow.protocol)
      {
      found = 1;

    //Devuelvo el indice del elemento que contiene el flow, pero es negativo, asi se sabe que es en sentido contrario.
      return i;
      }
*/

  }

//No hay indice 404, se devuelve como un codigo de error.
  return FLOW_NOT_FOUND;
}

// update de la inf del flow en sentido src->dst
int updateFlow_src(CircBuf buf, flow newFlow, directional_info extra_info ,int index)
{
   flow ThisFlow = buf.connections[index];
   ThisFlow.data.src_numPackets++;
   ThisFlow.data.src_totalBytes += extra_info.byteCount;
   ThisFlow.data.sttl += extra_info.ttl;
   //load se deberia calcular al final con totalBytes y alguna variable de tiempo
   ThisFlow.data.tcp_window += newFlow.data.tcp_window;
   //inter arrival sera la variable de tiempo / numpackets
   //mean es totalbytes / numpackets

}
// update de la inf del flow en sentido dst->src
int updateFlow_dst(CircBuf buf, flow newFlow,directional_info extra_info, int index)
{
  flow ThisFlow = buf.connections[index];
  ThisFlow.data.dst_numPackets++;
  ThisFlow.data.dst_totalBytes += extra_info.byteCount;
  ThisFlow.data.dttl += extra_info.ttl;
  //load se deberia calcular al final con totalBytes y alguna variable de tiempo
  ThisFlow.data.tcp_window += newFlow.data.tcp_window;
  //inter arrival sera la variable de tiempo / numpackets
  //mean es totalbytes / numpackets
  //http resp size?
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
void myPacketParser(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr, CircBuf buffer_circ)
{
  struct ip* iphdr;
  struct icmphdr* icmphdr;
  struct tcphdr* tcphdr;
  struct udphdr* udphdr;
  flow thisFlow;
  directional_info extra_info;

  char iphdrInfo[256], srcip[256], dstip[256];
  unsigned short id, seq;
  int srcPort, dstPort, byteCount;
  short int tcp_win, ind;



  // Skip the datalink layer header and get the IP header fields.
  packetptr += linkhdrlen;
  iphdr = (struct ip*)packetptr;

  strcpy(thisFlow.f_srcip, inet_ntoa(iphdr->ip_src));
  strcpy(thisFlow.f_dstip, inet_ntoa(iphdr->ip_dst));

  extra_info.byteCount = ntohs(iphdr->ip_len);
  extra_info.ttl = ntohs(iphdr->ip_ttl);
  //extra_info.time = nose de donde sacarlo

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

// Necesitare esta info para algunos parametros extra de TCP, podria servir para dar por finalizados los flows de este protocolo,
/*
      tcphdr->urg
      tcphdr->ack
      tcphdr->psh
      tcphdr->rst
      tcphdr->syn
      tcphdr->fin
*/
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
      printf("ICMP %s -> %s\n", srcip, dstip);
      printf("%s\n", iphdrInfo);
      memcpy(&id, (u_char*)icmphdr+4, 2);
      memcpy(&seq, (u_char*)icmphdr+6, 2);
      printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
             ntohs(id), ntohs(seq));
      break;
  }

  //Tenemos toda la informacion necesaria para mirar los flows.
  ind = fetch_flow(buffer_circ, thisFlow);

  //Hay que crear un nuevo flow en el buffer
  if(ind==FLOW_NOT_FOUND)
  {
      CircBuf_push(buffer_circ, thisFlow, extra_info);
  }
  else  //Ya existe el flow, donde hay que meter la informacion nueva?
  {
    if(isReversed(buffer_circ.connections[ind], thisFlow))
    {
      updateFlow_dst(buffer_circ, thisFlow,  extra_info ,ind);
    }
    else
    {
      updateFlow_src(buffer_circ, thisFlow,  extra_info ,ind);
    }
  }
  printf("Flow %s:%d -> %s:%d, proto: %s \n",thisFlow.f_srcip,thisFlow.f_srcPort,thisFlow.f_dstip,thisFlow.f_dstPort, thisFlow.protocol);
  //CircBuf_Print(buffer_circ);
}


void bailout(int signo)
{
    struct pcap_stat stats;


    if (pcap_stats(pd, &stats) >= 0)
    {
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
    }
    pcap_close(pd);
    exit(0);
}

int main(int argc, char **argv)
{
    char interface[256] = "", bpfstr[256] = "";
    int packets = 0, c, i;

    // Get the command line options, if any
    while ((c = getopt (argc, argv, "hi:n:")) != -1)
    {
        switch (c)
        {
        case 'h':
            printf("usage: %s [-h] [-i ] [-n ] []\n", argv[0]);
            exit(0);
            break;
        case 'i':
            strcpy(interface, optarg);
            break;
        case 'n':
            packets = atoi(optarg);
            break;
        }
    }

    // Get the packet capture filter expression, if any.
    for (i = optind; i < argc; i++)
    {
        strcat(bpfstr, argv[i]);
        strcat(bpfstr, " ");
    }
    CircBuf buffer_circ;
    printf("Starting buffer...\n" );
    CircBuf_Init(buffer_circ);
    printf("Buffer initialized.\n" );

    // Open libpcap, set the program termination signals then start
    // processing packets.
    if ((pd = open_pcap_socket(interface, bpfstr)))
    {
        signal(SIGINT, bailout);
        signal(SIGTERM, bailout);
        signal(SIGQUIT, bailout);
        capture_loop(pd, packets, (pcap_handler)myPacketParser);

      //dumpear el buffer, a ver que contiene.
        CircBuf_Print(buffer_circ);
        bailout(0);
    }
    exit(0);
}

/*
void parse_packet(u_char *user, struct pcap_pkthdr *packethdr,
                  u_char *packetptr)
{
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;

    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip*)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4*iphdr->ip_hl, ntohs(iphdr->ip_len));

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packetptr += 4*iphdr->ip_hl;
    switch (iphdr->ip_p)
    {
    case IPPROTO_TCP:
        tcphdr = (struct tcphdr*)packetptr;
        printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
               dstip, ntohs(tcphdr->dest));
        printf("%s\n", iphdrInfo);
        printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
               (tcphdr->urg ? 'U' : '*'),
               (tcphdr->ack ? 'A' : '*'),
               (tcphdr->psh ? 'P' : '*'),
               (tcphdr->rst ? 'R' : '*'),
               (tcphdr->syn ? 'S' : '*'),
               (tcphdr->fin ? 'F' : '*'),
               ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
               ntohs(tcphdr->window), 4*tcphdr->doff);
        break;

    case IPPROTO_UDP:
        udphdr = (struct udphdr*)packetptr;
        printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
               dstip, ntohs(udphdr->dest));
        printf("%s\n", iphdrInfo);
        break;

    case IPPROTO_ICMP:
        icmphdr = (struct icmphdr*)packetptr;
        printf("ICMP %s -> %s\n", srcip, dstip);
        printf("%s\n", iphdrInfo);
        memcpy(&id, (u_char*)icmphdr+4, 2);
        memcpy(&seq, (u_char*)icmphdr+6, 2);
        printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
               ntohs(id), ntohs(seq));
        break;
    }
    printf(
        "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
}
*/
