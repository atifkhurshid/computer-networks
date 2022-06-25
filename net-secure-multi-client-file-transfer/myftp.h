#ifndef MYFTP   /* Include guard */
#define MYFTP
#define BUFFER_SIZE  10000 				/* 10K buffer size for send and recv */
#define REPOSITORY	 "./data"			/* repository directory of server */ 

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct message_s {
	unsigned char protocol[5]; 			/* protocol string (5 bytes) */
	unsigned char type; 				/* type (1 byte) */
	unsigned int length; 				/* length (header + payload) (4 bytes) */
} __attribute__ ((packed));             /* removes spaces to give size = 10 bytes */


void printProgress (double percentage);
int sendn(SSL **ssl, void *buf, int buf_len, int header);
int recvn(SSL **ssl, void *buf, int buf_len, int header);
void send_file(SSL **ssl, unsigned char *filename, unsigned short server);
void save_file(SSL **ssl, unsigned char *filename, int filesize, unsigned short server);
void time_elapsed(double seconds, char *timestr);
int verify_certificate(X509* server_cert);
int init_ctx(SSL_CTX** ctx,SSL_METHOD** method);


#endif // MYFTP


