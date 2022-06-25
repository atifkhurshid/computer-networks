#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>	// "struct sockaddr_in"
#include <arpa/inet.h>	// "in_addr_t"
#include <sys/wait.h>
#include <dirent.h>		// "DIR, struct direct, readdir_r"
#include <stddef.h>		// "offsetof"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "myftp.h"

#define RSA_SERVER_CERT     	"cert.pem"		
#define RSA_SERVER_KEY      	"key.pem"

void main_loop(unsigned short port);
void server_list(SSL **ssl, struct message_s request, char *client_ip_address, unsigned short client_port);
void server_get(SSL **ssl, struct message_s get_request, char *client_ip_address, unsigned short client_port);
void server_put(SSL **ssl, struct message_s put_request, char *client_ip_address, unsigned short client_port);
void *child_function(void *input);
void load_server_certs(SSL_CTX** ctx);

typedef struct inputStructure 
{
    int client_sd;
	char client_ip_address[INET_ADDRSTRLEN];
	unsigned short client_port;
	SSL_CTX *ctx;
} inputStructure;

int main(int argc, char **argv){
	unsigned short port;
	if(argc != 2)
	{
		fprintf(stderr, "Usage: %s [port]\n", argv[0]);
		exit(1);
	}
	port = atoi(argv[1]);
	main_loop(port);

	return 0;
}

void main_loop(unsigned short port){
	int server_sd, client_sd;
	char client_ip_address[INET_ADDRSTRLEN];

	struct sockaddr_in sa_server, sa_client;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	SSL_CTX         *ctx;
	SSL_METHOD      *method;

	if (!init_ctx(&ctx, &method)) {
       fprintf(stderr,"Context initialisation failed.\n");
       exit(1);
    }    

    load_server_certs(&ctx);

	server_sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   								// Create a TCP Socket
	if(server_sd == -1){	
		perror("socket()");
		exit(1);
	}
																							// Making port usable in case server crashes
	long val = 1;
	if (setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(long)) < 0){
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}
	#ifdef SO_REUSEPORT
    if (setsockopt(server_sd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(long)) < 0) {
        perror("setsockopt(SO_REUSEPORT) failed");
    	exit(1);
    }
	#endif
																							//Setting up the port for the listening socket
	memset (&sa_server, 0, sizeof(sa_server));
	sa_server.sin_family      = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port        = htons (port);          /* Server Port number */
																							// After the setup has been done, invoke bind()
	if(bind(server_sd, (struct sockaddr*)&sa_server,sizeof(sa_server)) == -1){
		perror("bind()");
		exit(1);
	}
																							// Switch to listen mode by invoking listen()
	if( listen(server_sd, 5) == -1 ){
		perror("listen()");
		exit(1);
	}
	printf("[To stop the server: press Ctrl + C]\n");
	       
	while(1) {
		client_sd = accept(server_sd, (struct sockaddr*)&sa_client, &addrlen);					// Accept one client																	
		if(client_sd == -1){
			perror("accept()");
			exit(1);
		}
		fprintf(stderr, "Client %s:%u connected.\n", 
			inet_ntop(AF_INET,&(sa_client.sin_addr),client_ip_address,INET_ADDRSTRLEN) , ntohs(sa_client.sin_port));

		inputStructure *input = (inputStructure *)malloc(sizeof(inputStructure));
		input->client_sd = client_sd;
		strcpy(input->client_ip_address,client_ip_address);
		input->client_port = ntohs(sa_client.sin_port);
		input->ctx = ctx;
		pthread_t tid;
  		pthread_create(&tid, NULL, child_function, input);
	}																							// End of infinite, accepting loop.
	close(server_sd);
	SSL_CTX_free(ctx);
}

void *child_function(void *par_input) {
	int status;
	struct message_s request;

	char client_ip_address[INET_ADDRSTRLEN]; 
	unsigned short client_port;

	inputStructure *input = (inputStructure *)par_input;

	SSL *client_ssl;

	strcpy(client_ip_address, input->client_ip_address);
	client_port = input->client_port;

	client_ssl = SSL_new(input->ctx);
	SSL_set_fd(client_ssl, input->client_sd);
	int accept = SSL_accept(client_ssl);
	fprintf(stderr,"%s:%u SSL connection using %s: ",client_ip_address, client_port, SSL_get_cipher (client_ssl));
	/* Perform SSL Handshake on the SSL server */
	if (( accept != 1) || (SSL_get_cipher (client_ssl) == "NONE")) {
		fprintf(stderr, "FAILED\n");
		fprintf(stderr, "%s:%u Disconnected.\n", client_ip_address, client_port);
		return 0;
	}
	/* Informational output (optional) */
	fprintf(stderr,"SUCCESS\n");

	fprintf(stderr, "%s:%u Waiting for request: ", client_ip_address, client_port);

	status = recvn(&client_ssl, &request, sizeof(struct message_s), 1);

	if(status == -1) {
		perror("reading...");
		return 0;
	}
	if(status == 0) {	
		fprintf(stderr, "FAIL\n");																// nothing can be received.
		fprintf(stderr, "%s:%u No request received.\n", client_ip_address, client_port);
	}
	else {																						//Determine request type and choose srespective function
		if (request.type == 0xA1)
			server_list(&client_ssl, request, client_ip_address, client_port);
		else if (request.type == 0xB1)
			server_get(&client_ssl, request, client_ip_address, client_port);
		else if (request.type == 0xC1)
			server_put(&client_ssl, request, client_ip_address, client_port);
		else
			fprintf(stderr, "request.type()");
	}
	fprintf(stderr, "%s:%u Disconnected.\n", client_ip_address, client_port);
	close(input->client_sd);
	SSL_free(client_ssl);
	free(input);
}

void server_list(SSL **ssl, struct message_s request, char *client_ip_address, unsigned short client_port){
	int status, num_entries = 0;
	unsigned char *buffer = NULL;
	struct message_s reply;

  	DIR *dir;
  	struct dirent *entry;

  	fprintf(stderr,"LIST_REQUEST\n");
																						  		// Directory Reading Algorithm Source : 
																						  		//https://www.ibm.com/support/knowledgecenter/en/ssw_i5_54/apis/readdirr.htm
  	fprintf(stderr,"%s:%u Reading repository: ", client_ip_address, client_port);
  	if ((dir = opendir(REPOSITORY)) == NULL){
    	perror("opendir() error");
    	return;
  	}
  	else {                      																// Reading directory using dirent.h
  		buffer = (unsigned char *)malloc(256);
  		memset(buffer, '\0', 255);
    	while((entry = readdir(dir)) != NULL) {													// readdir(dir) returns directory entries one by one
      			if ((strcmp(entry->d_name, ".") != 0) && (strcmp(entry->d_name, "..") != 0)){	// Skipping ./ and ../
	      			num_entries++;
	      			buffer = (unsigned char *)realloc(buffer, 256 * num_entries);								// Allocating memeory for each filename 
	      			buffer = (unsigned char *)strcat((char *)buffer, entry->d_name);  											// Move filename to buffer
 	      			buffer = (unsigned char *)strcat((char *)buffer,"\n");
      		}
    	}
    	closedir(dir);
    	buffer = (unsigned char *)strcat((char *)buffer,"\0");
  	}
  	fprintf(stderr, "SUCCESS\n");

  	// Send LIST_REPLY
	strcpy((char *)reply.protocol, "myftp");
	reply.type = 0xA2;
	reply.length = htonl(sizeof(struct message_s) + strlen((const char *)buffer) + 1);

	fprintf(stderr,"%s:%u Sending LIST_REPLY: ", client_ip_address, client_port);
	status = sendn(ssl, &reply, sizeof(struct message_s), 1);
	if(status == -1) {
		perror("reading...");
		return;
	}
	if(status == 0)		// nothing can be received.
		fprintf(stderr, "No message received from %s:%u.\n", client_ip_address, client_port);
	else {
		fprintf(stderr, "SUCCESS\n");
		fprintf(stderr,"%s:%u Sending file list: ", client_ip_address, client_port);
		sendn(ssl, buffer, strlen((const char *)buffer) + 1, 0);
		if(status == -1) {
			perror("sending...");
			return;
		}
		if(status == 0)		// nothing can be received.
			fprintf(stderr, "%s:%u LIST: FAILED.\n", client_ip_address, client_port);
		else{
			fprintf(stderr, "SUCCESS\n");
			fprintf(stderr, "%s:%u LIST: SUCCESS\n", client_ip_address, client_port);
		}
	}	
}

void server_get(SSL **ssl, struct message_s get_request, char *client_ip_address, unsigned short client_port){	
	int status, size;
	unsigned char  *filename, *filepath;
	FILE *fp = NULL;
	struct message_s reply;

	fprintf(stderr,"GET_REQUEST.\n");

	size = ntohl(get_request.length) - sizeof(struct message_s);
	filename = (unsigned char *)malloc(size * sizeof(unsigned char));
	filepath = (unsigned char *)malloc((size + 5) * sizeof(unsigned char));

	fprintf(stderr,"%s:%u Waiting for filename: ", client_ip_address, client_port);
	status = recvn(ssl, filename, size, 0);					/* Receive Payload */
	if(status == -1) {
		perror("reading...");
		return;
	}
	else if(status == 0)
		perror("server_get() received nothing");
	else {
		fprintf(stderr,"%s\n", filename);
		strcpy((char *)reply.protocol, "myftp");
		reply.length = htonl(sizeof(struct message_s));

		filepath = (unsigned char *) strcpy((char *)filepath, "data/");
		filepath = (unsigned char *) strcat((char *)filepath, (const char *)filename);

		fprintf(stderr,"%s:%u Searching for %s: ", client_ip_address, client_port, filename); 	// Searching for file requested.
		fp = fopen((const char *)filepath, "rb");
		if (fp){																			  	// If found, read and send
			fprintf(stderr,"SUCCESS\n");
			reply.type = 0xB2;
			fprintf(stderr,"%s:%u Sending GET_REPLY: ", client_ip_address, client_port);
			status = sendn(ssl, &reply, sizeof(struct message_s), 1);
			if(status == -1) {
				perror("sending...");
				return;
			}
			else if(status == 0)
				perror("server_get() sent nothing");
			else
				fprintf(stderr,"SUCCESS\n");
				fprintf(stderr,"%s:%u Sending %s...\n", client_ip_address, client_port, filename);
				send_file(ssl, filepath, 1);														// Function to read and send files
				fprintf(stderr, "%s:%u GET: SUCCESS\n", client_ip_address, client_port);	

		}
		else{																					// If file not found
			fprintf(stderr,"FAIL\n");
			reply.type = 0xB3;
			fprintf(stderr,"%s:%u Sending GET_REPLY: ", client_ip_address, client_port);
			status = sendn(ssl, &reply, sizeof(struct message_s), 1);
			fprintf(stderr,"SUCCESS\n");
			fprintf(stderr, "%s:%u GET: FAILED\n", client_ip_address, client_port);
		}
	}
}

void server_put(SSL **ssl, struct message_s put_request, char *client_ip_address, unsigned short client_port){
	int status, size;
	unsigned char  *filename, *filepath;
	struct message_s put_reply;

	fprintf(stderr,"PUT_REQUEST\n");

	size = ntohl(put_request.length) - sizeof(struct message_s);
	filename = (unsigned char *)malloc(size * sizeof(unsigned char));
	filepath = (unsigned char *)malloc((size + 5) * sizeof(unsigned char));
	fprintf(stderr,"%s:%u Waiting for filename: ", client_ip_address, client_port);
	status = recvn(ssl, filename, size, 0);					/* Receive Payload */
	if(status == -1) {
		perror("reading...");
		return;
	}
	else if(status == 0)
		perror("server_put() received nothing");
	else {
		fprintf(stderr,"%s\n", filename);
		strcpy((char *)put_reply.protocol, "myftp");
		put_reply.length = htonl(sizeof(struct message_s));
		put_reply.type = 0xC2;
		fprintf(stderr,"%s:%u Sending PUT_REQUEST: ", client_ip_address, client_port);
		status = sendn(ssl, &put_reply, sizeof(struct message_s), 1);
		if(status == -1) {
			perror("sending...");
			return;
		}
		else if(status == 0)
			perror("server_put() sent nothing");
		else {
			fprintf(stderr,"SUCCESS\n");
			filepath = (unsigned char *)strcpy((char *)filepath, "data/");
			filepath = (unsigned char *) strcat((char *)filepath, (const char *)filename);

			fprintf(stderr,"%s:%u Waiting for FILE_DATA: ", client_ip_address, client_port);
			struct message_s file_data;
			recvn(ssl, &file_data, sizeof(struct message_s), 1);
			if(status == -1) {
				perror("waiting...");
				return;
			}
			else if(status == 0){
				perror("server_put(): received nothing");
				fprintf(stderr, "%s:%u PUT: FAIL\n", client_ip_address, client_port);
			}
			else {
				fprintf(stderr,"SUCCESS\n");
				fprintf(stderr,"%s:%u Waiting for %s...\n", client_ip_address, client_port, filename);
				save_file(ssl, filepath, ntohl(file_data.length) - sizeof(struct message_s), 1);			// Function to save files
				fprintf(stderr, "%s:%u PUT: SUCCESS\n", client_ip_address, client_port);
			}
		}
	}		
}

void load_server_certs(SSL_CTX** ctx) {
	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(*ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/* set password for the private key file. Use this statement carefully */
	SSL_CTX_set_default_passwd_cb_userdata(*ctx, (char*)"4430");
	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(*ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) { 
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(*ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		exit(1);
	}
}
