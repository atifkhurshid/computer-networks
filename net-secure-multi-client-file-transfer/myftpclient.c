#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>	// "struct sockaddr_in"
#include <arpa/inet.h>	// "in_addr_t"
#include <sys/wait.h>
#include <netdb.h>
#include "myftp.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RSA_CLIENT_CA_CERT      "cacert.pem"

void main_task(in_addr_t ip, unsigned short port, char *command, unsigned char *filename);
void list(SSL **ssl);
void get(SSL **ssl, unsigned char *filename);
void put(SSL **ssl, unsigned char *filename);
int load_client_certs(SSL_CTX** ctx);

int main(int argc, char **argv)
{
	in_addr_t ip;
	unsigned short port;

	if(argc != 5 && argc != 4){
		fprintf(stderr, "Usage: %s  <server ip addr>  <server port>  <list|get|put>  <file>\n", argv[0]);
		exit(1);
	}
	if( (ip = inet_addr(argv[1])) == -1 ){
		perror("inet_addr()");
		exit(1);
	}

	port = atoi(argv[2]);

	if (argc == 4 && strcmp(argv[3], "list") == 0)
		main_task(ip, port, argv[3], NULL);
	else if (argc == 5 && (strcmp(argv[3], "get") == 0 || strcmp(argv[3],"put") == 0))
		main_task(ip, port, argv[3], (unsigned char *)argv[4]);
	else
		fprintf(stderr, "Usage: %s  <server ip addr>  <server port>  <list|get|put>  <file>\n", argv[0]);
		exit(1);		
	return 0;
}


void main_task(in_addr_t ip, unsigned short port, char *command, unsigned char *filename) {
	int sd;
	struct sockaddr_in addr;
	char server_ip_address[INET_ADDRSTRLEN];
	unsigned int addrlen = sizeof(struct sockaddr_in);

	SSL_CTX         *ctx;
	SSL             *ssl;
	SSL_METHOD      *method;
	X509            *server_cert;

    if (!init_ctx(&ctx, &method)) {
       fprintf(stderr, "Context initialisation failed\n");
       exit(1);
    }    

    load_client_certs(&ctx);

	sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); 	// Create a TCP socket
	if(sd == -1){
		perror("socket()");
		exit(1);
	}
	long val = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(long)) == -1){
		perror("setsockopt");
		exit(1);
	}
	#ifdef SO_REUSEPORT
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(long)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
    	exit(1);
    }
	#endif

	// Below 4 lines: Set up the destination with IP address and port number.
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = htons(port);

	if( connect(sd, (struct sockaddr *) &addr, addrlen) == -1 ){		// connect to the destintation
		perror("connect()");
		exit(1);
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		fprintf(stderr, "Failed to create ssl structure\n");
		exit(-1);
	}

	/* Assign the socket into the SSL structure */
	SSL_set_fd(ssl, sd);

	/* Perform SSL Handshake on the SSL client */
	if (SSL_connect(ssl) == -1) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	/* Get the server's certificate */
	server_cert = SSL_get_peer_certificate(ssl);
	/* Verify server's certificate  */    
	verify_certificate(server_cert);

	if(strcmp(command, "list") == 0) 
		list(&ssl);
	else if(strcmp(command, "get") == 0)
		get(&ssl, filename);
	else if(strcmp(command, "put") == 0)
		put(&ssl, filename);
	else
		printf("Sent nothing.\n");

	/*--------------- SSL closure ---------------*/
	/* Shutdown the client side of the SSL connection */

	if (SSL_shutdown(ssl) == -1) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}
	if (close(sd) == -1) {
		ERR_print_errors_fp(stderr);
		exit(-1);
	}
	/* Free the SSL structure */
	SSL_free(ssl);
	/* Free the SSL_CTX structure */
	SSL_CTX_free(ctx);
}

void list(SSL **ssl){
	struct message_s list_request, list_reply;
	unsigned char *buffer, size;
	int status;

	// Send LIST_REQUEST
	strcpy((char *)list_request.protocol, "myftp");
	list_request.type = 0xA1;
	list_request.length = htonl(sizeof(struct message_s));

	status = sendn(ssl, &list_request, sizeof(struct message_s), 1);
	if(status == -1) {
		perror("Sending...");
		exit(1);
	}
	if(status == 0)		
		fprintf(stderr, "No message sent to server!\n");
	else { 																							// If GET_REQUEST sent correctly
																									// Wait for LIST_REPLY
		status = recvn(ssl, &list_reply, sizeof(struct message_s), 1);
		if(status == -1) {
			perror("reading...");
			exit(1);
		}
		if(status == 0)		
			fprintf(stderr, "No message received from server!\n");
		else { 																						// If LIST_REPLY recieved
																									// Read directory list into buffer
			size = ntohl(list_reply.length) - sizeof(struct message_s); 
			buffer = (unsigned char *)malloc(size * sizeof(unsigned char));

			status = recvn(ssl, buffer, size, 0);
			if(status == -1) {
				perror("reading...");
				exit(1);
			}
			if(status == 0)		
				fprintf(stderr, "No data received from server!\n");
			else 
				// Print directory
				fprintf(stderr,"%s", buffer);	
		}
	}	
}

void get(SSL **ssl, unsigned char *filename){
	struct message_s get_request, get_reply;
																										//Send GET_REQUEST
	strcpy((char *)get_request.protocol, "myftp");
	get_request.type = 0xB1;
	get_request.length = htonl(sizeof(struct message_s) + strlen((const char *)filename) + 1);

	sendn(ssl, &get_request, sizeof(struct message_s), 1);						/* Send Header */	
	sendn(ssl, filename, strlen((const char *)filename) + 1, 0);								/* Send Payload */

																										// Wait for GET_REPLY
	recvn(ssl, &get_reply, sizeof(struct message_s), 1);

	if (get_reply.type == 0xB2){ 																		// If file exists at server
		struct message_s file_data;
																										// Recieve FILE_DATA
		recvn(ssl, &file_data, sizeof(struct message_s), 1);
		
		fprintf(stderr, "Downloading %s...\n", filename);
		clock_t begin = time(NULL);
		save_file(ssl, filename, ntohl(file_data.length) - sizeof(struct message_s), 0);   				//Function to recieve files
		clock_t end = time(NULL);
		char timestr[20];
		time_elapsed(difftime(end, begin), timestr);													// Function to calculate time elapsed wile downloading file
		fprintf(stderr, "Download complete. Time Elapsed: %s\n", timestr);
	}
	else if (get_reply.type == 0xB3) 																	// If file does not exist at server
		fprintf(stderr, "Error 404: File not found.\n");
	else 
		perror("Incorrect get_reply type\n");
}

void put(SSL **ssl, unsigned char *filename){
	struct message_s put_request, put_reply;
	FILE *fp = NULL;
																										// Try to open file
	fp = fopen((const char *)filename, "rb");
	if (fp) { 																							// If file found in local directory
																										// Send PUT_REQUEST
		strcpy((char *)put_request.protocol, "myftp");
		put_request.type = 0xC1;
		put_request.length = htonl(sizeof(struct message_s) + strlen((const char *)filename) + 1);					//Calculate file size and send to server

		sendn(ssl, &put_request, sizeof(struct message_s), 1);
		sendn(ssl, filename, strlen((const char *)filename) + 1, 0);														// Send filename to server

		recvn(ssl, &put_reply, sizeof(struct message_s), 1);    											// Wait for PUT_REPLY

		fprintf(stderr, "Uploading...\n");
		clock_t begin = time(NULL);
		send_file(ssl, filename, 0);																		// Function to read and send file
		clock_t end = time(NULL);
		
		char timestr[20];
		time_elapsed(difftime(end, begin), timestr);   													// Function to calculate time elapsed wile sending file
		fprintf(stderr, "Upload complete. Time Elapsed: %s\n", timestr);
	}
	else 
		perror("put()");
}

int load_client_certs(SSL_CTX** ctx) {
	/* Load the RSA CA certificate into the SSL_CTX structure */
	/* This will allow this client to verify the server's     */
	/* certificate.                                           */
    if (!SSL_CTX_load_verify_locations(*ctx, RSA_CLIENT_CA_CERT, NULL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/* Set flag in context to require peer (server) certificate */
	/* verification */
	SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(*ctx, 1);

    return 1;
}







