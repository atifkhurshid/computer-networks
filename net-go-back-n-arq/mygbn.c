#include "mygbn.h"

/*************locks and Global Variables used by Sener*******************/

pthread_mutex_t base_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t timer_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t trigger_resend = PTHREAD_COND_INITIALIZER;
pthread_cond_t send_end = PTHREAD_COND_INITIALIZER;
pthread_cond_t ack_end = PTHREAD_COND_INITIALIZER;
sem_t base_sem;

/*****************Sender Helper Functions******************************/

void timer_handler(int32_t sigalarm);
void end_handler(int32_t end_alaram);
void *thread_senddata(void *arg);
int32_t read_packets(int32_t packet_number, int32_t len, unsigned char *target, unsigned char *source); 
void *thread_getack(void *arg);
void *thread_resend(void *args);  
void resend_packet(struct mygbn_sender *mygbn_sender, int32_t resend_counter); 
void *thread_end_ack(void *arg);
void *thread_end_send(void *arg);

/*****************Receiver Helper Functions******************************/

int32_t send_ack(struct mygbn_receiver *mygbn_receiver, int32_t seqNum);

/****************************Signal Handlers*****************************/

void timer_handler(int32_t sigalarm){
	pthread_cond_signal(&trigger_resend);
}

void end_handler(int32_t end_alaram) {
	pthread_cond_signal(&send_end);
}

/****************************Sender's Functions***************************/

void mygbn_init_sender(struct mygbn_sender *mygbn_sender, char *ip, int32_t port, int32_t N, int32_t timeout) {
	/* Setting up SIGALARM to run timer_handler */
	signal(SIGALRM, timer_handler);
	/* Create socket */
	if ((mygbn_sender->sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ERROR: cannot create socket\n");
		exit(-1);
	}
	/* memset sender_addr */
	memset(&(mygbn_sender->sender_addr), 0, sizeof(mygbn_sender->sender_addr));
	/*initialise sender_addr*/
	mygbn_sender->sender_addr.sin_family = AF_INET;
	mygbn_sender->sender_addr.sin_addr.s_addr = inet_addr(ip);
	mygbn_sender->sender_addr.sin_port = htons(port);
	/*initialise mygbn_sender */

	mygbn_sender->N = N;
	mygbn_sender->timeout = timeout;
	mygbn_sender->packets_to_send = 0;
	mygbn_sender->start_base = 1;

	mygbn_sender->nextseqnum = (int32_t *)malloc(sizeof(int32_t));
	mygbn_sender->base_ptr = (int32_t *)malloc(sizeof(int32_t));
	mygbn_sender->end_ack = (uint32_t *)malloc(sizeof(uint32_t));
	*(mygbn_sender->base_ptr) = 1;
	*(mygbn_sender->nextseqnum) = 1;
	*(mygbn_sender->end_ack) = 0;

	sem_init(&base_sem, 0, N);
}

int32_t mygbn_send(struct mygbn_sender *mygbn_sender, unsigned char *buf, int32_t len) {
	pthread_t tid1;
	int32_t *ret_val;

	mygbn_sender->packets_to_send = len / MAX_PAYLOAD_SIZE + 1;
	mygbn_sender->start_base = *(mygbn_sender->base_ptr);
	mygbn_sender->source = buf;
	mygbn_sender->length = len;

	pthread_create(&tid1, NULL, thread_senddata, (void *)mygbn_sender);
	pthread_join(tid1, (void **)&ret_val);

	printf("Sent %d bytes\n", *ret_val);
	return *ret_val;
}

void *thread_senddata(void *arg) {
	struct mygbn_sender *mygbn_sender = (struct mygbn_sender *)arg;
	pthread_t tid_1, tid_2;
	int i = 0;
	int32_t ret;  //  To chech for errnos

	int *ret_val = (int32_t *)malloc(sizeof(int32_t));
	*ret_val = 0; // To calculate data sent

	pthread_create(&tid_1, NULL, thread_getack, (void *)mygbn_sender);
	pthread_create(&tid_2, NULL, thread_resend, (void *)mygbn_sender);

	for (i = 1; i <= mygbn_sender->packets_to_send; i++) {
		struct MYGBN_Packet packet;
		packet.protocol[0] = 'g';
		packet.protocol[1] = 'b';
		packet.protocol[2] = 'n';
		packet.type = 0XA0;
		packet.length = htonl(12 + read_packets(i, mygbn_sender->length, packet.payload,\
		                                                          mygbn_sender->source));
		packet.seqNum = htonl((*(mygbn_sender->nextseqnum)));
		*ret_val += ntohl(packet.length);
		*ret_val -= 12;
		*(mygbn_sender->nextseqnum) = *(mygbn_sender->nextseqnum) + 1;
		sem_wait(&base_sem);
		printf("Sending Packet: %d\n", *(mygbn_sender->nextseqnum) - 1);
		ret = sendto(mygbn_sender->sd, (unsigned char *)&packet, sizeof(packet), 0,\
		             (struct sockaddr *)&(mygbn_sender->sender_addr), sizeof(struct sockaddr));
		if (ret == -1) //errno
			*ret_val = -1;
		if (i == 1)
			alarm(mygbn_sender->timeout);
	}

	pthread_join(tid_1, NULL);
	pthread_join(tid_2, NULL);
	pthread_exit((void *)ret_val);
}

int32_t read_packets(int32_t packet_number, int32_t len, unsigned char *target, unsigned char *source) {
	int32_t i = 0, j = 0;
	int32_t upper_bound = packet_number * MAX_PAYLOAD_SIZE;
	int32_t lower_bound = upper_bound - MAX_PAYLOAD_SIZE;

	if (upper_bound > len)
		upper_bound = len;

	for (i = lower_bound; i < upper_bound; i++)
		target[j++] = source[i];

	return upper_bound - lower_bound;
}

void *thread_getack(void *arg) {
	struct mygbn_sender *mygbn_sender = (struct mygbn_sender *)arg;
	struct MYGBN_Packet packet;
	int32_t i, base_incrementer;
	socklen_t addrLen = sizeof(mygbn_sender->sender_addr);

	while (1) //loop until all the packets have been successully acked
	{
		recvfrom(mygbn_sender->sd, &packet, sizeof(packet), 0, \
		          (struct sockaddr *)&(mygbn_sender->sender_addr), &addrLen); //Wait for packet
		if (packet.type == 0XA1) { //If ack packet
			uint32_t seqNum = ntohl(packet.seqNum);
			if (seqNum >= *(mygbn_sender->base_ptr)) { // If correctly acked
				printf("Received Ack[%d]: ACCEPTED\n", seqNum);
				base_incrementer = seqNum - *(mygbn_sender->base_ptr) + 1;
				*(mygbn_sender->base_ptr) = 1 + seqNum;
				alarm(mygbn_sender->timeout); //restart timer on receipt of base packets.

				for (i = 0; i < base_incrementer; i++) //multiple posts due to receipt of cummalative acknowledgment
					sem_post(&base_sem);

				pthread_mutex_lock(&base_lock);
					if (*(mygbn_sender->base_ptr) >= mygbn_sender->start_base + \
					                   mygbn_sender->packets_to_send) //packets acked, 
					{
						pthread_mutex_unlock(&base_lock); //relase lock and exit loop
						break;
					}
				pthread_mutex_unlock(&base_lock);
			}
			else 
				printf("Received Ack[%d]: DECLINED [Unexpected ACK]\n", seqNum);
		}
	}
	alarm(0); //stop timer when all packets acked.
	pthread_cond_signal(&trigger_resend); //signal reend thread to recheck sent packets and exit.
	pthread_exit(NULL);
}

//thread function to resend packets
void *thread_resend(void *args)  {
	struct mygbn_sender *mygbn_sender = (struct mygbn_sender *)args;
	int32_t resend_counter = 0;
	while (1) {
		pthread_mutex_lock(&base_lock);

			if (*(mygbn_sender->base_ptr) == mygbn_sender->start_base + \
				                       mygbn_sender->packets_to_send) {
				pthread_mutex_unlock(&base_lock);
				break;
			}

		pthread_mutex_unlock(&base_lock);
		pthread_cond_wait(&trigger_resend, &timer_lock);	

			resend_packet(mygbn_sender, resend_counter);
			resend_counter++;

		pthread_mutex_unlock(&timer_lock);
	}
	pthread_exit(NULL);
}

void resend_packet(struct mygbn_sender *mygbn_sender, int32_t resend_counter) {
	int32_t i;
	int32_t first_packet = *(mygbn_sender->base_ptr);      //The first packet to send
	int32_t last_packet = *(mygbn_sender->nextseqnum) - 1; //last sent packet
	int32_t offset = mygbn_sender->start_base - 1;         // index offset for read_packets

	struct MYGBN_Packet packet; //packet construction
	packet.protocol[0] = 'g';
	packet.protocol[1] = 'b';
	packet.protocol[2] = 'n';

	packet.type = 0XA0; 

	for (i = first_packet; i <= last_packet; i++) {
		packet.length = htonl(12 + read_packets(i - offset, mygbn_sender->length,\
		                       packet.payload, mygbn_sender->source));
		packet.seqNum = htonl((i));
		printf("*****[%d]Resending packet: %d\n", resend_counter,ntohl(packet.seqNum));
		sendto(mygbn_sender->sd, (unsigned char *)&packet, sizeof(packet), 0,\
		        (struct sockaddr *)&(mygbn_sender->sender_addr), sizeof(struct sockaddr));
	}
	alarm(mygbn_sender->timeout);
}


void mygbn_close_sender(struct mygbn_sender *mygbn_sender)
{
	pthread_t tid;
	signal(SIGALRM, end_handler);

	pthread_create(&tid, NULL, thread_end_send, (void *)mygbn_sender);
	pthread_join(tid, NULL);

	close(mygbn_sender->sd);
	free(mygbn_sender->base_ptr);
	free(mygbn_sender->nextseqnum);
	printf("Sender closed!\n");
}

void *thread_end_send(void *arg) {
	pthread_t tid;
	struct mygbn_sender *mygbn_sender = (struct mygbn_sender *)arg;

	struct MYGBN_Packet packet;
	packet.protocol[0] = 'g';
	packet.protocol[1] = 'b';
	packet.protocol[2] = 'n';
	packet.type = 0XA2;
	packet.length = htonl(12);
	packet.seqNum = htonl((*(mygbn_sender->nextseqnum)));
	
	pthread_create(&tid, NULL, thread_end_ack, (void *)mygbn_sender);
	pthread_mutex_lock(&base_lock);

	while (1) {
		if (*(mygbn_sender->end_ack) == 3) {
			pthread_cond_signal(&ack_end);
			pthread_mutex_unlock(&base_lock);
			break;
		}

		*(mygbn_sender->end_ack) = *(mygbn_sender->end_ack) + 1;
		alarm(mygbn_sender->timeout);
		printf("Sending End packet: %d\n", *(mygbn_sender->end_ack));
		sendto(mygbn_sender->sd, (unsigned char *)&packet, sizeof(packet), 0,\
		       (struct sockaddr *)&(mygbn_sender->sender_addr), sizeof(struct sockaddr));
		pthread_mutex_unlock(&base_lock);
		pthread_cond_wait(&send_end, &base_lock);
	}
	pthread_cancel(tid);
	pthread_exit(NULL);
}

void *thread_end_ack(void *arg) {
	struct mygbn_sender *mygbn_sender = (struct mygbn_sender *)arg;
	struct MYGBN_Packet packet;
	socklen_t addrLen = sizeof(mygbn_sender->sender_addr);

	while (1) {
		recvfrom(mygbn_sender->sd, &packet, sizeof(packet), 0,\
		         (struct sockaddr *)&(mygbn_sender->sender_addr), &addrLen);
		uint32_t seqNum = ntohl(packet.seqNum);
		if (packet.type == 0XA1) { 
			if (seqNum >= *(mygbn_sender->base_ptr)) { 
				printf("Received Ack END[%d]: ACCEPTED\n", seqNum);
				pthread_mutex_lock(&base_lock);

					*(mygbn_sender->end_ack) = 3;	// Stop sending end packets
					*(mygbn_sender->base_ptr) = 1 + seqNum;

				pthread_mutex_unlock(&base_lock);
				break;
			}
			else
				printf("Received Ack END[%d]: DECLINED [Unexpected ACK]\n", seqNum);
		}
	}
	pthread_cond_signal(&send_end);
	pthread_exit(NULL);
}

/****************************Receiver's Functions***************************/

void mygbn_init_receiver(struct mygbn_receiver *mygbn_receiver, int32_t port) {
	int32_t one = 1;
	/* create socket */
	if ((mygbn_receiver->sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ERROR: cannot create socket\n");
		exit(-1);
	}
	/* set socket option for reuse*/
	if (setsockopt(mygbn_receiver->sd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)) < 0) {
		perror("ERROR: cannot set socket option\n");
		exit(-1);
	}
	/* prepare the address structure */
	memset(&(mygbn_receiver->server_addr), 0, sizeof(mygbn_receiver->server_addr));
	(mygbn_receiver->server_addr).sin_family = AF_INET;
	(mygbn_receiver->server_addr).sin_addr.s_addr = htonl(INADDR_ANY);
	(mygbn_receiver->server_addr).sin_port = htons(port);

	/* bind the socket to network structure */
	if (bind(mygbn_receiver->sd, (struct sockaddr *)&(mygbn_receiver->server_addr),\
	    sizeof(mygbn_receiver->server_addr)) < 0) {
			perror("ERROR: cannot bind\n");
			exit(-1);
	}

	mygbn_receiver->expectedseqnum = 1;
}


int32_t mygbn_recv(struct mygbn_receiver *mygbn_receiver, unsigned char *buf, int32_t len) { 
	int32_t data_read = 0, i = 0, payload_length = MAX_PAYLOAD_SIZE;
	uint32_t seqNum = 0;
	struct MYGBN_Packet packet;
	socklen_t addrLen = sizeof(mygbn_receiver->server_addr);

	while (data_read != len && payload_length >= 512) {
		//receive data from client
		recvfrom(mygbn_receiver->sd, &packet, sizeof(packet), 0, \
			     (struct sockaddr *)&(mygbn_receiver->server_addr), &addrLen);
		payload_length = ntohl(packet.length) - 12;
		seqNum = (ntohl(packet.seqNum));
		printf("Expecting packet %d: ", mygbn_receiver->expectedseqnum);
		//check for valid expected seqnum
		if (seqNum == mygbn_receiver->expectedseqnum) {
			printf("RECEIVED\n");
			mygbn_receiver->expectedseqnum++;
			if (packet.type == 0XA2) { // If end packet
				printf("END PACKET!\n");
				payload_length = 512;
				mygbn_receiver->expectedseqnum = 1;
				if (send_ack(mygbn_receiver, seqNum) != -1) {
					printf("Sending Final Ack:%d\n", seqNum);
					printf("Client Closed!\n");
				}
				else
					printf("Sending Final Ack:%d FAILED\n", seqNum);
			}
			else { //write data to the buffer
				for (i = data_read; i < data_read + payload_length; i++)
					buf[i] = packet.payload[i - data_read];
				//update the data read by the function call
				data_read += payload_length;
				if (send_ack(mygbn_receiver, seqNum) != -1)
					printf("Sending Ack:%d\n", seqNum);
				else
					printf("Sending Ack:%d FAILED\n", seqNum);	
			}
		}
		else {
			printf("FAILED\n");
			printf("Received packet:%d. Invalid sequence number\n", seqNum);
			payload_length = 512;
			if (send_ack(mygbn_receiver, mygbn_receiver->expectedseqnum - 1) != -1)
				printf("Sending Ack:%d\n", mygbn_receiver->expectedseqnum - 1);
			else
				printf("Sending Ack:%d FAILED\n", mygbn_receiver->expectedseqnum - 1);
		}
	}
	return data_read;
}


int32_t send_ack(struct mygbn_receiver *mygbn_receiver, int32_t seqNum) {
	struct MYGBN_Packet packet;
	packet.protocol[0] = 'g';
	packet.protocol[1] = 'b';
	packet.protocol[2] = 'n';
	packet.type = 0XA1;
	packet.length = htonl(12);

	packet.seqNum = htonl(seqNum);
	return sendto(mygbn_receiver->sd, &packet, sizeof(packet), 0,\
		   (struct sockaddr *)&(mygbn_receiver->server_addr), sizeof(mygbn_receiver->server_addr));
}

void mygbn_close_receiver(struct mygbn_receiver *mygbn_receiver) {
	close(mygbn_receiver->sd);
}
