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

#define MAXLEN 4096
#define FLOW_NOT_FOUND 404
#define CIRCBUFSIZE 100





pcap_t* pd;
int linkhdrlen;

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
//    pcap_if_t* interface_list;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;

    //pcap_if_t *interface_list;
    //result = pcap_findalldevs(&interface_list,errbuf);

// Deberia funcionar con esta funcion, pero da segmentation fault
    //pcap_findalldevs(&interface_list, errbuf);

    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    //if (!*device && !(device = interface_list->name))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }
    //printf("%s\n",device );
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
  int loss;
}directional_info;

typedef struct sample_data
{
  signed int src_numPackets, dst_numPackets;
  signed int src_totalBytes, dst_totalBytes;
  signed int sttl, dttl;
  float s_load, d_load;
  signed int s_loss;
  signed int tcp_window; //source
  double s_inpkt;
  double total_arrival_time;
  struct timespec first_tmp;
  struct timespec current_tmp_src;
  struct timespec current_tmp;  //para el calculo final de tiempo
  float s_mean, d_mean;
  signed int http_resp_size;
  signed int same_src_and_dst_ip_ct;
  signed int same_src_ip_and_dst_pt_ct;
} sample_data;

typedef struct flow
{
  char f_srcip[256],f_dstip[256];
  signed int f_srcPort, f_dstPort;
  char* protocol;// tengo que cambiarlo por un mapeo de int (enum)
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


//Main buffer declaration (Global)
CircBuf buf;
struct pcap_stat curr_stats, stats;

// Inicializacion de buffer circular
//void CircBuf_Init(CircBuf buf)
void CircBuf_Init()
{
  buf.head = 0;
  buf.tail = 0;
  buf.size = CIRCBUFSIZE;
}
//int CircBuf_Print(CircBuf buf)

int CircBuf_push(flow newFlow, directional_info extra_info, struct timespec time)
{

  newFlow.data.src_numPackets = 1;
  newFlow.data.dst_numPackets = 0;
  newFlow.data.src_totalBytes = extra_info.byteCount;
  newFlow.data.dst_totalBytes = 0;
  newFlow.data.sttl = extra_info.ttl;
  newFlow.data.dttl = 0;
  newFlow.data.s_loss = extra_info.loss;
  newFlow.data.s_inpkt = 0.0;
  newFlow.data.total_arrival_time = 0.0;
  newFlow.data.first_tmp = time;
  newFlow.data.current_tmp = time;
  newFlow.data.current_tmp_src = time;
  newFlow.data.s_load = 0.0;
  newFlow.data.d_load = 0.0;
  newFlow.data.s_mean = 0.0;
  newFlow.data.d_mean = 0.0;

  //newFlow.data.http_resp_size = 0; //este solo deberia llenarse en caso de que llegue un paquete desde un puerto 80 o 443

  //printf("%d\n", buf.tail );
  buf.connections[buf.tail++] = newFlow;
    //memcpy(&buf.connections[buf.tail++],&newFlow, sizeof(newFlow));
    if (buf.tail == buf.size)
    {
      buf.tail = 0;
    }
    return buf.tail;
}
//flow Circbuf_pop(CircBuf buf)
flow Circbuf_pop()
{
  flow thisFlow;
  thisFlow = buf.connections[buf.head++];
  if (buf.head == buf.size)
  {
    buf.head = 0;
  }
  return thisFlow;
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


double calculate_time(struct timespec t1, struct timespec t2)
{
  long seconds = t2.tv_sec - t1.tv_sec;
  long ns = t2.tv_nsec - t1.tv_nsec;

  if (t1.tv_nsec > t2.tv_nsec)  // clock underflow
  {
     --seconds;
     ns += 1000000;
   }
 return (double)seconds*1000 + (double)ns/(double)1000000;
}

//Introduciendo un flow devuelve el flow con la informacion de los calculos completa
flow Calculate_Features(flow thisFlow)
{
    int i;
    int same_src_and_dst_ip = 0;
    int same_src_ip_and_dst_pt = 0;
    flow bufElement;
    double total_time;

    for(i=0; i< buf.size; i++)
    {
      bufElement = buf.connections[i];
      if(strcmp(bufElement.f_srcip,thisFlow.f_srcip) == 0 && strcmp(bufElement.f_dstip,thisFlow.f_dstip) == 0)
        same_src_and_dst_ip++;
      if(strcmp(bufElement.f_srcip,thisFlow.f_srcip) == 0 &&  bufElement.f_dstPort == thisFlow.f_dstPort)
        same_src_ip_and_dst_pt++;
    }
    total_time = calculate_time(thisFlow.data.first_tmp, thisFlow.data.current_tmp);
    //printf("total time %f, sinpkt %f\n", total_time,thisFlow.data.total_arrival_time);

    //avoid inf values
    if(total_time==0.0)
      total_time = 1.0;

    thisFlow.data.s_inpkt = thisFlow.data.total_arrival_time/thisFlow.data.src_numPackets;
    thisFlow.data.s_mean = (float)thisFlow.data.src_totalBytes/(float)thisFlow.data.src_numPackets;
    thisFlow.data.d_mean = (float)thisFlow.data.dst_totalBytes/(float)thisFlow.data.dst_numPackets;

    //avoid nan values
    if(thisFlow.data.dst_numPackets == 0)
      thisFlow.data.d_mean = 0.0;

    thisFlow.data.s_load = (float)thisFlow.data.src_totalBytes/total_time;
    thisFlow.data.d_load = (float)thisFlow.data.dst_totalBytes/total_time;
    thisFlow.data.same_src_and_dst_ip_ct = same_src_and_dst_ip;
    thisFlow.data.same_src_ip_and_dst_pt_ct = same_src_ip_and_dst_pt;


    return thisFlow;
}

/*
•  Destination packet count.
•  Source bytes.
•  Source TTL.
•  Destination TTL.
•  Source load.
•  Destination Load.
•  Source loss.
•  Source inter-arrival packet time.
•  Source TCP window advertisement.
•  Mean flow packet size transmitted by source.
•  Mean flow packet size transmitted by destination.
•  The content size of the data transferred from a HTTP service.
•  Number of connections with the same source address and destination port in 100 connections according to the last time.
•  Number of connections with the same source address and destination address in 100 connections according to the last time.
*/
typedef struct Sample
{

  signed int src_numPackets, dst_numPackets;
  signed int src_totalBytes;
  signed int sttl, dttl;
  float s_load, d_load;
  signed int s_loss;
  float s_inpkt;
  signed int tcp_window; //source
  float s_mean, d_mean;
  signed int http_resp_size;
  signed int same_src_and_dst_ip_ct;
  signed int same_src_ip_and_dst_pt_ct;
} Sample;

void send_Sample(flow flowToSend)
{
  //Generar sample con la estructura de datos definitiva para enviar
  Sample sample;

  sample.src_numPackets = flowToSend.data.src_numPackets;
  sample.dst_numPackets = flowToSend.data.dst_numPackets;
  sample.src_totalBytes = flowToSend.data.src_totalBytes;
  sample.sttl = flowToSend.data.sttl;
  sample.dttl = flowToSend.data.dttl;
  sample.s_load = flowToSend.data.s_load;
  sample.d_load = flowToSend.data.d_load;
  sample.s_inpkt = (float)flowToSend.data.s_inpkt;
  sample.tcp_window = flowToSend.data.tcp_window;
  sample.s_mean = flowToSend.data.s_mean;
  sample.d_mean = flowToSend.data.d_mean;
  sample.http_resp_size = flowToSend.data.http_resp_size;
  sample.same_src_and_dst_ip_ct = flowToSend.data.same_src_and_dst_ip_ct;
  sample.same_src_ip_and_dst_pt_ct = flowToSend.data.same_src_ip_and_dst_pt_ct;

  //Abrir comunicaciones socket udp con el programa ML y enviar sample
  SocketCommunication(sample);
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

int CircBuf_Print()
{
  flow sample;
    for(int i=0; i< buf.size; i++)
    {
        printf("i=%d, Flow %s:%d -> %s:%d , proto: %s \n"
        ,i, buf.connections[i].f_srcip,buf.connections[i].f_srcPort ,buf.connections[i].f_dstip
        , buf.connections[i].f_dstPort, buf.connections[i].protocol);
        if(buf.connections[i].protocol == NULL)
          return(-1);
        sample = buf.connections[i];
        sample = Calculate_Features(sample);
        send_Sample(sample);


    }
    /*
    printf("%d,%d,%d,%d,%f,%f,%d,%f,%d,%f,%f,%d,%d,%d\n",
      sample.data.dst_numPackets, sample.data.src_totalBytes, sample.data.sttl, sample.data.dttl,
      sample.data.s_load, sample.data.d_load, sample.data.s_loss, sample.data.s_inpkt,
      sample.data.tcp_window, sample.data.s_mean, sample.data.d_mean, sample.data.http_resp_size,
      sample.data.same_src_and_dst_ip_ct, sample.data.same_src_ip_and_dst_pt_ct);
    send_Sample(sample);
    */
    printf("\n");
    return(0);
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
void myPacketParser(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr)
{
  struct ip* iphdr;
  struct icmphdr* icmphdr;
  struct tcphdr* tcphdr;
  struct udphdr* udphdr;


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

  //pcap_stats(pd, &curr_stats);

  //printf("sizeof flow %ld\n",sizeof(flow));
  //id = -1;

  // Skip the datalink layer header and get the IP header fields.
  //Hay paquetes
  clock_gettime(CLOCK_REALTIME,&timestamp);
  //printf("this timestamp, sec: %ld, nsec: %ld \n",timestamp.tv_sec, timestamp.tv_nsec );
  packetptr += linkhdrlen;
  iphdr = (struct ip*)packetptr;

  strcpy(thisFlow.f_srcip, inet_ntoa(iphdr->ip_src));
  strcpy(thisFlow.f_dstip, inet_ntoa(iphdr->ip_dst));
  thisFlow.data.http_resp_size = 0;
  extra_info.byteCount = ntohs(iphdr->ip_len);
  extra_info.ttl = iphdr->ip_ttl;

//Funciona bien, pero va como por chunks, podria no dar un comportamiento esperado.
      pcap_stats(pd, &stats);
      //printf("%d packets received\n", stats.ps_recv - curr_stats.ps_recv );
      extra_info.loss = (stats.ps_drop - curr_stats.ps_drop) + (stats.ps_ifdrop - curr_stats.ps_ifdrop);
      //printf("%d packets dropped\n\n", stats.ps_drop);
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

      break;

  case IPPROTO_ICMP:
      icmphdr = (struct icmphdr*)packetptr;
      thisFlow.protocol = "ICMP";
      //printf("im an icmp packet\n");

      break;
  }

  //Tenemos toda la informacion necesaria para mirar los flows.
  ind = fetch_flow( thisFlow);
  //printf("fetched %d\n", ind);

  //Hay que crear un nuevo flow en el buffer
  if(ind==FLOW_NOT_FOUND)
  {
     id =  CircBuf_push(thisFlow, extra_info, timestamp);
  }
  else  //Ya existe el flow, donde hay que meter la informacion nueva?
  {
    if(isReversed(buf.connections[ind], thisFlow))
    {
      //printf(" updating dst->src\n" );
      updateFlow_dst( thisFlow,  extra_info ,ind, timestamp);
    }
    else
    {
      //printf(" updating src->dst\n" );
      updateFlow_src( thisFlow,  extra_info ,ind, timestamp);
    }
  }
  //if(ind != FLOW_NOT_FOUND)
    //printf("buf pos %d, code %d\n", id, ind );
  //printf("Flow %s:%d -> %s:%d, proto: %s \n",thisFlow.f_srcip,thisFlow.f_srcPort,thisFlow.f_dstip,thisFlow.f_dstPort, thisFlow.protocol);
      //if(thisFlow.f_srcPort == 80)
      //  printf("Flow %s:%d -> %s:%d, proto: %s \n",thisFlow.f_srcip,thisFlow.f_srcPort,thisFlow.f_dstip,thisFlow.f_dstPort, thisFlow.protocol);

/*
  printf("%d,%d,%d,%d,%f,%f,%d,%f,%d,%f,%f,%d,%d,%d\n",
    buf.connections[tail].data.dst_numPackets, buf.connections[tail].data.src_totalBytes, buf.connections[tail].data.sttl, buf.connections[tail].data.dttl,
    buf.connections[tail].data.s_load, buf.connections[tail].data.d_load, buf.connections[tail].data.s_loss, buf.connections[tail].data.s_inpkt,
    buf.connections[tail].data.tcp_window, buf.connections[tail].data.s_mean, buf.connections[tail].data.d_mean, buf.connections[tail].data.http_resp_size,
    buf.connections[tail].data.same_src_and_dst_ip_ct, buf.connections[tail].data.same_src_ip_and_dst_pt_ct);
*/
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
    CircBuf_Print(buf);
    //send_Sample(buf.connections[0]);
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

    printf("Starting buffer...\n" );
    CircBuf_Init(buf);
    printf("Buffer initialized.\n" );

    // Open libpcap, set the program termination signals then start
    // processing packets.
    if ((pd = open_pcap_socket(interface, bpfstr)))
    {
        signal(SIGINT, bailout);
        signal(SIGTERM, bailout);
        signal(SIGQUIT, bailout);
        //alarm(60);
        //signal(SIGALRM,bailout);
        //pcap_set_timeout(pd, 500);
        pcap_stats(pd, &stats);
        pcap_stats(pd, &curr_stats);
        capture_loop(pd, packets, (pcap_handler)myPacketParser);

      //dumpear el buffer, a ver que contiene.
        bailout(0);
    }
    exit(0);
}

int SocketCommunication(Sample sample)
{
  struct  sockaddr_in     server;
  struct  hostent         *hp;

  int sd, server_len;
  int port = 4545;
  char* host = "localhost";
  char rbuf[MAXLEN], sbuf[MAXLEN];
  //Create socket
  if ( (sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 )
  {
          printf("socket creation failed");
          exit(1);
  }
  bzero((char *)&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    //server.sin_port = port;

    if ((hp = gethostbyname(host)) == NULL) {
        fprintf(stderr, "Can't get server's IP address\n");
        close(sd);
        exit(1);
    }
    server_len = sizeof(server);

    if (sendto(sd, &sample, sizeof(Sample), 0, (struct sockaddr *)
        &server, server_len) == -1)
    {
      fprintf(stderr, "sendto error\n");
      close(sd);
      exit(1);
    }
    //rbuf
    if (recvfrom(sd, rbuf, sizeof(int), 0, (struct sockaddr *)
        &server, &server_len) < 0)
    {
      fprintf(stderr, "recvfrom error\n");
      close(sd);
      exit(1);
    }
    close(sd);
    printf("%s\n",rbuf );
return 0;
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
