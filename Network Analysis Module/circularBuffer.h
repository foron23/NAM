
#include <time.h>
#include "dataStructures.h"
#include <stdint.h>

#define CIRCBUFSIZE 100
#define MAXLEN 4096

/*
pthread_mutex_t pkt_lock;
pthread_mutex_t flow_lock;

pthread_cond_t pkt_ovr_cond;
pthread_cond_t flow_ovr_cond;
pthread_cond_t pkt_und_cond;
pthread_cond_t flow_und_cond;

int pkt_count;
int flow_count;
*/
typedef struct CircBuf_Flow
{
  int head;
  int tail;
  int size;
  flow connections[CIRCBUFSIZE];
} CircBuf_Flow;

typedef struct CircBuf_Pkt
{
  int head;
  int tail;
  int size;
  //uint8_t packets[MAXLEN];
  //https://www.eskimo.com/~scs/cclass/int/sx9b.html
  uint8_t* packets[MAXLEN];

} CircBuf_Pkt;

//CircBuf_Pkt pkt_buf;
//CircBuf_Flow buf;

void CircBuf_Init_Flow();
void CircBuf_Init_Pkt();
int CircBuf_Flow_push(flow newFlow, directional_info extra_info, struct timespec time);
flow CircBuf_Flow_pop();
int CircBuf_Pkt_push(uint8_t *packetptr);
uint8_t* CircBuf_Pkt_pop();
int CircBuf_Print();
void CircBuf_Finish();
