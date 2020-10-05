#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include "dataStructures.h"
#include "circularBuffer.h"
#include "calculation.h"
//#include "sampler.h"

#define CIRCBUFSIZE 100




CircBuf_Pkt pkt_buf;
CircBuf_Flow buf;

pthread_mutex_t pkt_lock;
pthread_mutex_t flow_lock;

sem_t sem_pkt_in;
sem_t sem_pkt_out;
sem_t sem_flow_in;
sem_t sem_flow_out;

//pthread_cond_t pkt_ovr_cond = PTHREAD_COND_INITIALIZER;
//pthread_cond_t flow_ovr_cond = PTHREAD_COND_INITIALIZER;
//pthread_cond_t pkt_und_cond = PTHREAD_COND_INITIALIZER;
//pthread_cond_t flow_und_cond = PTHREAD_COND_INITIALIZER;
//pthread_cond_t pkt_cond = PTHREAD_COND_INITIALIZER;
//pthread_cond_t flow_cond = PTHREAD_COND_INITIALIZER;

int pkt_count;
int flow_count;



void CircBuf_Init_Flow()
{

  if (pthread_mutex_init(&flow_lock, NULL) != 0) {
      printf("\n flow mutex init has failed\n");
      exit(1);
  }
  sem_init(&sem_flow_in, 1, CIRCBUFSIZE);
  sem_init(&sem_flow_out, 1, 0);
  //flow_cond  = PTHREAD_COND_INITIALIZER;
  flow_count = 0;
  buf.head = 0;
  buf.tail = 0;
  buf.size = CIRCBUFSIZE;
}
void CircBuf_Init_Pkt()
{

  if (pthread_mutex_init(&pkt_lock, NULL) != 0) {
      printf("\n packet mutex init has failed\n");
      exit(1);
  }
  sem_init(&sem_pkt_in, 1, MAXLEN);
  sem_init(&sem_pkt_out, 1, 0);
  //pkt_cond  = PTHREAD_COND_INITIALIZER;
  pkt_count = 0;
  pkt_buf.head = 0;
  pkt_buf.tail = 0;
  pkt_buf.size = MAXLEN;
}

int CircBuf_Flow_push(flow newFlow, directional_info extra_info, struct timespec time)
{
  int value;


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
  #ifdef DEBUG
    sem_getvalue(&sem_flow_in, &value);
    printf("***************FLOW*************** PUSH SEM IN VALUE: %d \n", value);
  #endif
  sem_wait(&sem_flow_in);
  pthread_mutex_lock(&flow_lock);

  #ifdef DEBUG
    printf("Flow buffer tail: %d\n", buf.tail );
  #endif
  buf.connections[buf.tail++] = newFlow;

  if (buf.tail == buf.size)
  {
    buf.tail = 0;
  }

  pthread_mutex_unlock(&flow_lock);
  sem_post(&sem_flow_out);
  #ifdef DEBUG
    sem_getvalue(&sem_flow_out, &value);
    printf("***************FLOW*************** PUSH SEM OUT VALUE: %d \n", value);
  #endif

    return buf.tail;
}


flow CircBuf_Flow_pop()
{
  flow thisFlow;
  int value;

  #ifdef DEBUG
    sem_getvalue(&sem_flow_out, &value);
    printf("***************FLOW*************** PUSH SEM OUT VALUE: %d \n", value);
  #endif

  sem_wait(&sem_flow_out);
  pthread_mutex_lock(&flow_lock);
  #ifdef DEBUG
    printf("flow buffer head: %d\n",buf.head  );
  #endif
  thisFlow = buf.connections[buf.head++];

  if (buf.head == buf.size)
  {
    buf.head = 0;
  }

  sem_post(&sem_flow_in);
  pthread_mutex_unlock(&flow_lock);
  #ifdef DEBUG
    sem_getvalue(&sem_flow_in, &value);
    printf("***************FLOW*************** PUSH SEM IN VALUE: %d \n", value);
  #endif

  return thisFlow;
}

int CircBuf_Pkt_push(uint8_t *packetptr)
{

  struct ip* iphdr;
  iphdr = (struct ip*)packetptr;
  int value;
  #ifdef DEBUG
    sem_getvalue(&sem_pkt_in, &value);
    printf("***************PACKET*************** PUSH SEM IN VALUE: %d \n", value);
  #endif
  sem_wait(&sem_pkt_in);
  pthread_mutex_lock(&pkt_lock);
  #ifdef DEBUG
    printf("Packet buffer tail: %d \n", pkt_buf.tail);
  #endif

  pkt_buf.packets[pkt_buf.tail++] = packetptr;
  if (pkt_buf.tail == pkt_buf.size)
  {
    pkt_buf.tail = 0;
  }

  pthread_mutex_unlock(&pkt_lock);
  sem_post(&sem_pkt_out);
  #ifdef DEBUG
    sem_getvalue(&sem_pkt_out, &value);
    printf("***************PACKET*************** PUSH SEM OUT VALUE: %d \n", value);
  #endif
  return pkt_buf.tail;
}

uint8_t* CircBuf_Pkt_pop()
{
  uint8_t *packetptr;

  int value;
  #ifdef DEBUG
    sem_getvalue(&sem_pkt_out, &value);
    printf("***************PACKET*************** POP SEM OUT VALUE: %d \n", value);
  #endif
  sem_wait(&sem_pkt_out);
  pthread_mutex_lock(&pkt_lock);
  #ifdef DEBUG
    printf("Packet buffer head: %d \n", pkt_buf.head);
  #endif
  packetptr = pkt_buf.packets[pkt_buf.head++];

  if (pkt_buf.head == pkt_buf.size)
  {
    pkt_buf.head = 0;
  }

  pthread_mutex_unlock(&pkt_lock);
  sem_post(&sem_pkt_in);
  #ifdef DEBUG
    sem_getvalue(&sem_pkt_in, &value);
    printf("***************PACKET*************** POP SEM IN VALUE: %d \n", value);
  #endif

  return packetptr;
}

int CircBuf_Flow_Print()
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


      }

    printf("\n");
    return(0);
}

void CircBuf_Finish()
{
  pthread_mutex_destroy(&pkt_lock);
  pthread_mutex_destroy(&flow_lock);
  sem_destroy(&sem_pkt_in);
  sem_destroy(&sem_pkt_out);
  sem_destroy(&sem_flow_in);
  sem_destroy(&sem_flow_out);

}
