
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "dataStructures.h"
#include "circularBuffer.h"
#include "calculation.h"
#include "sampler.h"

#define CIRCBUFSIZE 100
#define MAXLEN 4096


CircBuf_Flow buf;
CircBuf_Pkt pkt_buf;


void CircBuf_Init_Flow()
{
  buf.head = 0;
  buf.tail = 0;
  buf.size = CIRCBUFSIZE;
}
void CircBuf_Init_Pkt()
{
  pkt_buf.head = 0;
  pkt_buf.tail = 0;
  pkt_buf.size = MAXLEN;
}

int CircBuf_Flow_push(flow newFlow, directional_info extra_info, struct timespec time)
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
flow CircBuf_Flow_pop()
{
  flow thisFlow;
  thisFlow = buf.connections[buf.head++];
  if (buf.head == buf.size)
  {
    buf.head = 0;
  }
  return thisFlow;
}

int CircBuf_Pkt_push(uint8_t *packetptr)
{
  memcpy(&pkt_buf.packets[pkt_buf.tail++],&packetptr, sizeof(packetptr));
  //pkt_buf[pkt_buf.tail++];
  //memcpy(&buf.connections[buf.tail++],&newFlow, sizeof(newFlow));
    if (pkt_buf.tail == pkt_buf.size)
    {
      pkt_buf.tail = 0;
    }
    return pkt_buf.tail;
}

uint8_t* CircBuf_Pkt_pop()
{
  uint8_t *packetptr;
  memcpy(&packetptr,&pkt_buf.packets[pkt_buf.head++], sizeof(packetptr));
  if (pkt_buf.head == pkt_buf.size)
  {
    pkt_buf.head = 0;
  }
  return packetptr;
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
