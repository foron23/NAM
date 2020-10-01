#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include "globals.h"
//#include "dataStructures.h"
//#include "circularBuffer.h"
#include "globals.h"
#include "calculation.h"
#include "sampler.h"

//Parametros??
int port;
char* host;

int sampler()
{
flow flowToSend;
while(1)
{
  printf("Another sampler round \n");
  //printf("Getting Sample...");
  flowToSend = CircBuf_Flow_pop();
  printf("Sample popped,\n");
  flowToSend = Calculate_Features(flowToSend);
  printf("Sending Sample\n");
  send_Sample(flowToSend);
}
  return 0;

}

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


int SocketCommunication(Sample sample)
{
  struct  sockaddr_in     server;
  struct  hostent         *hp;

  int sd, server_len;
  //printf("this is host %s port %d\n",host, port );
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
    printf("Sent.\n");
    //rbuf
    /*
    if (recvfrom(sd, rbuf, sizeof(int), 0, (struct sockaddr *)
        &server, &server_len) < 0)
    {
      fprintf(stderr, "recvfrom error\n");
      close(sd);
      exit(1);
    }
    printf("Response received.\n");
`*/
    close(sd);
    //printf("%s\n",rbuf );
return 0;
}
