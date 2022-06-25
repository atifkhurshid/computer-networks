/*
 * mygbn.h
 */

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include<signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <semaphore.h>
#ifndef __mygbn_h__
#define __mygbn_h__

#define MAX_PAYLOAD_SIZE 512

struct MYGBN_Packet
{
  unsigned char protocol[3]; /* protocol string (3 bytes) "gbn" */
  unsigned char type;        /* type (1 byte) */
  uint32_t seqNum;       /* sequence number (4 bytes) */
  uint32_t length;       /* length(header+payload) (4 bytes) */
  unsigned char payload[MAX_PAYLOAD_SIZE];
  /* payload data */
};

struct mygbn_sender
{
  int32_t sd;
  struct sockaddr_in sender_addr;
  int32_t N;
  int32_t timeout;
  int32_t* base_ptr;
  int32_t packets_to_send;
  uint32_t* end_ack;
  int32_t start_base;
  int32_t* nextseqnum; 
  int32_t length;
  unsigned char *source;
  // GBN sender socket
  // ... other member variables
};
void timer_handler(int32_t sigalarm);
void mygbn_init_sender(struct mygbn_sender *mygbn_sender, char *ip, int32_t port, int32_t N, int32_t timeout);
int32_t mygbn_send(struct mygbn_sender *mygbn_sender, unsigned char *buf, int32_t len);
void mygbn_close_sender(struct mygbn_sender *mygbn_sender);
void alarm_handler(int32_t );

struct mygbn_receiver
{
  int32_t sd; // GBN receiver socket
  struct sockaddr_in sender_addr;
  struct sockaddr_in server_addr;
  int32_t expectedseqnum; //the seqNum of expected inorder packet

};

void mygbn_init_receiver(struct mygbn_receiver *mygbn_receiver, int32_t port);
int32_t mygbn_recv(struct mygbn_receiver *mygbn_receiver, unsigned char *buf, int32_t len);
void mygbn_close_receiver(struct mygbn_receiver *mygbn_receiver);

#endif
