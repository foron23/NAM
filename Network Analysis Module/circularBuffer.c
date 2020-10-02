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
#define MAXLEN 4096




CircBuf_Pkt pkt_buf;
CircBuf_Flow buf;

pthread_mutex_t pkt_lock;
pthread_mutex_t flow_lock;

//www.csc.villanova.edu/~mdamian/threads/posixsem.html
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

//int CircBuf_Flow_push(flow* newFlow, directional_info extra_info, struct timespec time)
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

//Usando las referencias salen flows vacios?
    /*
      newFlow->data.src_numPackets = 1;
      newFlow->data.dst_numPackets = 0;
      newFlow->data.src_totalBytes = extra_info.byteCount;
      newFlow->data.dst_totalBytes = 0;
      newFlow->data.sttl = extra_info.ttl;
      newFlow->data.dttl = 0;
      newFlow->data.s_loss = extra_info.loss;
      newFlow->data.s_inpkt = 0.0;
      newFlow->data.total_arrival_time = 0.0;
      newFlow->data.first_tmp = time;
      newFlow->data.current_tmp = time;
      newFlow->data.current_tmp_src = time;
      newFlow->data.s_load = 0.0;
      newFlow->data.d_load = 0.0;
      newFlow->data.s_mean = 0.0;
      newFlow->data.d_mean = 0.0;
`*/
  //newFlow.data.http_resp_size = 0; //este solo deberia llenarse en caso de que llegue un paquete desde un puerto 80 o 443
  sem_wait(&sem_flow_in);
  pthread_mutex_lock(&flow_lock);
  //printf("flow mutex in push\n" );

  //printf("%d\n", buf.tail );
  printf("(push)flow buf tail %d\n", buf.tail );
  memcpy(&buf.connections[buf.tail++],&newFlow,sizeof(newFlow));
  //buf.connections[buf.tail++] = newFlow;

    //memcpy(&buf.connections[buf.tail++],&newFlow, sizeof(newFlow));
    if (buf.tail == buf.size)
    {
      buf.tail = 0;
    }

    sem_post(&sem_flow_out);
    pthread_mutex_unlock(&flow_lock);

    //printf("flow mutex out push\n" );


    return buf.tail;
}
//flow Circbuf_pop(CircBuf buf)
flow CircBuf_Flow_pop()
{
  flow thisFlow;


  sem_wait(&sem_flow_out);
  pthread_mutex_lock(&flow_lock);
  //printf("flow mutex in pop\n" );

  //thisFlow = buf.connections[buf.head++];
  printf("(pop)flow head %d\n",buf.head  );
  memcpy(&thisFlow,&buf.connections[buf.head++],sizeof(thisFlow));

  if (buf.head == buf.size)
  {
    buf.head = 0;
  }

  sem_post(&sem_flow_in);
  pthread_mutex_unlock(&flow_lock);
  //printf("flow mutex out pop\n" );

  return thisFlow;
}

int CircBuf_Pkt_push(uint8_t *packetptr)
{

  struct ip* iphdr;
  //uint8_t* mypoint;
  iphdr = (struct ip*)packetptr;
  //printf("size of packet %ld ",ntohs(iphdr->ip_len) * sizeof(uint8_t));
  //printf("size of packet ip pointer array %d \n",ntohs(iphdr->ip_len)*ntohs(iphdr->ip_len) * sizeof(uint8_t));
  //int length  = ntohs(iphdr->ip_len);
  //(uint8_t*)malloc( ntohs(iphdr->ip_len) * sizeof(uint8_t));
  //mypoint =

  sem_wait(&sem_pkt_in);
  pthread_mutex_lock(&pkt_lock);
  //printf("pkt mutex in push\n" );
  pkt_buf.packets[pkt_buf.tail] = (uint8_t *)malloc( ntohs(iphdr->ip_len) * sizeof(uint8_t));
  //printf("size of packet placeholder %ld \n",sizeof(pkt_buf.packets[pkt_buf.tail]));
  //printf("(push)pkt_buf tail %d\n", pkt_buf.tail);
  memcpy(&pkt_buf.packets[pkt_buf.tail++],&packetptr, ntohs(iphdr->ip_len) * sizeof(uint8_t));
  //pkt_buf[pkt_buf.tail++];
  //memcpy(&buf.connections[buf.tail++],&newFlow, sizeof(newFlow));
    if (pkt_buf.tail == pkt_buf.size)
    {
      pkt_buf.tail = 0;
    }

  sem_post(&sem_pkt_out);
  pthread_mutex_unlock(&pkt_lock);
  //printf("pkt mutex out push\n\n" );

    return pkt_buf.tail;
}

uint8_t* CircBuf_Pkt_pop()
{
  uint8_t *packetptr;


  sem_wait(&sem_pkt_out);
  pthread_mutex_lock(&pkt_lock);
  //printf("pkt mutex in pop\n" );
//Creo que el problema de los pop proviene de la asignacion de memoria hecha aqui.
  memcpy(&packetptr,&pkt_buf.packets[pkt_buf.head], sizeof(pkt_buf.packets[pkt_buf.head]));
  //free(pkt_buf.packets[pkt_buf.head]);
  //printf("(pop)pkt_buf head %d\n", pkt_buf.head );
  pkt_buf.head++;
  if (pkt_buf.head == pkt_buf.size)
  {
    pkt_buf.head = 0;
  }

  sem_post(&sem_pkt_in);
  pthread_mutex_unlock(&pkt_lock);
  //printf("pkt mutex out pop\n" );

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
        //send_Sample(sample);


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

void CircBuf_Finish()
{
  pthread_mutex_destroy(&pkt_lock);
  pthread_mutex_destroy(&flow_lock);
  sem_destroy(&sem_pkt_in);
  sem_destroy(&sem_pkt_out);
  sem_destroy(&sem_flow_in);
  sem_destroy(&sem_flow_out);

}
