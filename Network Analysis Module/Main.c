#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "dataStructures.h"
#include "globals.h"
#include "calculation.h"
#include "sniffer.h"
#include "analyzer.h"
#include "sampler.h"


int port = 4545;
char *host = "localhost";

int debug = 0;
int packets = 0, c, i;
char interface[256] = "", bpfstr[256] = "";

void *sniffer_handler(void *snifferTh)
{
printf("Initializing sniffer thread \n");
sniffer();

/* the function must return something - NULL will do */
return NULL;

}

void *analyzer_handler(void *analyzeTh)
{
printf("Initializing analyzer thread \n");
PacketAnalyzer();
/* the function must return something - NULL will do */
return NULL;

}

void *sampler_handler(void *samplerTh)
{
printf("Initializing sampler thread \n");
sampler();

/* the function must return something - NULL will do */
return NULL;

}

int main(int argc, char **argv)
{

// Get the command line options, if any
while ((c = getopt (argc, argv, "hi:n:p:m")) != -1)
{
    switch (c)
    {
    case 'h':
        printf("usage: %s [-h] [-i ] [-n ] [-p ] [-m ] []\n", argv[0]);
        exit(0);
        break;
    case 'i':
        strcpy(interface, optarg);
        break;
    case 'n':
        packets = atoi(optarg);
        break;
    case 'p':
        port = atoi(optarg);
        break;
    case 'm':
        //strcpy(host, optarg);
        memcpy(&host,&optarg, sizeof(host));
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
CircBuf_Init_Flow();
CircBuf_Init_Pkt();
printf("Buffer initialized.\n" );


/* this variables are our references to the other threads */
pthread_t SnifferThread, AnalyzeThread, SamplerThread;

/* create the threads for the processes */
if(pthread_create(&SnifferThread, NULL, sniffer_handler, 0))
{

  fprintf(stderr, "Error creating sniffer thread\n");
  return 1;

}
if(pthread_create(&AnalyzeThread, NULL, analyzer_handler, 0))
{

  fprintf(stderr, "Error creating analyzer thread\n");
  return 1;

}
if(pthread_create(&SamplerThread, NULL, sampler_handler, 0))
{

  fprintf(stderr, "Error creating sampler thread\n");
  return 1;

}


if(pthread_join(SnifferThread, NULL)) {
fprintf(stderr, "Error joining sniffer thread\n");
return 2;
}
if(pthread_join(AnalyzeThread, NULL)) {
fprintf(stderr, "Error joining analyzer thread\n");
return 2;
}
if(pthread_join(SamplerThread, NULL)) {
fprintf(stderr, "Error joining sampler thread\n");
return 2;
}

CircBuf_Finish();
printf("Program finished.\n" );
exit(0);
}
