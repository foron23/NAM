#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "globals.h"
#include "calculation.h"
#include "sampler.h"

int port;
char* host;

int sampler()
{
flow flowToSend;
while(1)
{

  #ifdef DEBUG
    printf("Another sampler round \n");
    printf("Getting Sample...\n");
  #endif
  flowToSend = CircBuf_Flow_pop();
  #ifdef DEBUG
    printf("Sample popped.\n");
  #endif
  flowToSend = Calculate_Features(flowToSend);

  #ifdef DEBUG
    printf("Sending Sample\n");
  #endif
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


  #ifdef DEBUG
    printf("%d,%d,%d,%d,%f,%f,%d,%f,%d,%f,%f,%d,%d,%d\n",
      flowToSend.data.dst_numPackets, flowToSend.data.src_totalBytes, flowToSend.data.sttl, flowToSend.data.dttl,
      flowToSend.data.s_load, flowToSend.data.d_load, flowToSend.data.s_loss, flowToSend.data.s_inpkt,
      flowToSend.data.tcp_window, flowToSend.data.s_mean, flowToSend.data.d_mean, flowToSend.data.http_resp_size,
      flowToSend.data.same_src_and_dst_ip_ct, flowToSend.data.same_src_ip_and_dst_pt_ct);
  #endif

  //Abrir comunicaciones socket udp con el programa ML y enviar sample
  SocketCommunication(sample);
}


int SocketCommunication(Sample sample)
{
  struct  sockaddr_in     server;
  struct  hostent         *hp;

  int sd, server_len;
  #ifdef DEBUG
    printf("this is host %s port %d\n",host, port );
  #endif
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
    printf("------------------------------------------------------------------------------>Sent.\n");
    //rbuf

    if (recvfrom(sd, rbuf, sizeof(int), 0, (struct sockaddr *)
        &server, &server_len) < 0)
    {
      fprintf(stderr, "recvfrom error\n");
      close(sd);
      exit(1);
    }
    printf("Response received.\n");

    close(sd);
    //printf("%d\n",atoi(rbuf) );
return 0;
}
