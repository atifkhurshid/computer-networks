#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>		//time()
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>	// "struct sockaddr_in"
#include <arpa/inet.h>	// "in_addr_t"
#include <sys/wait.h>
#include <errno.h>
#include "myftp.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60

extern int errno;

// Used to print progress bar
// Source: https://stackoverflow.com/questions/14539867/how-to-display-a-progress-indicator-in-pure-c-c-cout-printf
void printProgress (double percentage) {
    int val = (int) (percentage * 100);
    int lpad = (int) (percentage * PBWIDTH);
    int rpad = PBWIDTH - lpad;
    printf ("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
    printf("\e[?25l");
    fflush (stdout);
} 

// Re-implementation of send()
// Ensures complete transfer of data
// Source: TA - Tutorial 3
int sendn(SSL **ssl, void *buf, int buf_len, int header){
	int n_left = buf_len;
	int n;
	if (header == 1) {
		while(n_left > 0) {
			if ((n = SSL_write(*ssl, (struct message_s *)buf + (buf_len - n_left), n_left)) < 0) {
				if (errno == EINTR)
					n = 0;
				else
					return -1;
			} else if (n == 0) {
				return 0;
			}
			n_left -= n;
		}
		return buf_len;
	} else {
		while(n_left > 0) {
			if ((n = SSL_write(*ssl, (unsigned char *)buf + (buf_len - n_left), n_left)) < 0) {
				if (errno == EINTR)
					n = 0;
				else
					return -1;
			} else if (n == 0) {
				return 0;
			}
			n_left -= n;
		}
		return buf_len;
	}
}

// Re-implementation of recv()
// Ensures complete transfer of data
// Source: TA - Tutorial 3
int recvn(SSL **ssl, void *buf, int buf_len, int header){
	int n_left = buf_len;
	int n;
	if (header == 1) {
		while(n_left > 0) {
			if ((n = SSL_read(*ssl, (struct message_s *)buf + (buf_len - n_left), n_left)) < 0) {
				if (errno == EINTR)
					n = 0;
				else
					return -1;
			} else if (n == 0) {
				return 0;
			}
			n_left -= n;
		}
		return buf_len;
	} else {
		while(n_left > 0) {
			if ((n = SSL_read(*ssl, (unsigned char *)buf + (buf_len - n_left), n_left)) < 0) {
				if (errno == EINTR)
					n = 0;
				else
					return -1;
			} else if (n == 0) {
				return 0;
			}
			n_left -= n;
		}
		return buf_len;		
	}
}

// Sends file_data header followed by file
void send_file(SSL **ssl, unsigned char *filename, unsigned short server){
	int status, bytes_sent = 0, send_size, ret, read, filesize, buf_size;
	unsigned char *buffer;
	struct message_s file_data;
	FILE *fp = fopen((const char *)filename, "rb");
	if (!fp) {																			// Check if file can be opened
		perror("send_file()");
		exit(1);
	}
																						// Method to find size of file : 
																						// https://www.tutorialspoint.com/c_standard_library/c_function_ftell.htm
	fseek (fp, 0, SEEK_END);
 	filesize = (int)ftell (fp);															// Find file size
 	fseek (fp, 0, SEEK_SET);
	strcpy((char *)file_data.protocol, "myftp");
	file_data.length = htonl(sizeof(struct message_s) + filesize);
	file_data.type = 0xFF;

	status = sendn(ssl, &file_data, sizeof(struct message_s), 1);							// Send FILE_DATA header

	if (status == -1){
		perror("sending...");
		exit(1);
	}
	if (status == 0){
		perror("send_file() sent 0 bytes");
	}

	if (filesize < BUFFER_SIZE) {														// Setting buffer size
		buffer = (unsigned char *) malloc(filesize * sizeof(char));										
		buf_size = filesize;
	} else {
		buffer = (unsigned char *) malloc(BUFFER_SIZE * sizeof(char));
		buf_size = BUFFER_SIZE;
	}

	bytes_sent = 0;
	if (!server)																		// Only show progress bar for client
		printProgress(0.0);
	send_size = filesize;
	do{
		read = fread(buffer, 1, buf_size, fp);											// Read file in buffer_size pieces and send after each read
		ret = sendn(ssl, buffer, read, 0);													 
		if (ret == -1){
			perror("sending...");
			exit(1);
		}
		if (ret == 0 && filesize != 0){
			perror("send_file() sent 0 bytes");
		}
		else{
			bytes_sent += ret;
			if (!server)			
				printProgress((double)bytes_sent/filesize);
		}
	} while (bytes_sent < filesize);
	if (!server)
		printf("\n");
	free(buffer);
	fclose (fp);
}

// Stores received file in buffer to file with name "filename"
void save_file(SSL **ssl, unsigned char *filename, int filesize, unsigned short server){
	FILE *fp;
	int ret= 0, recv_size= 0;
	int bytes_read = 0, size_left=0, buf_size = 0;
	unsigned char *buffer = NULL;

	if (filesize < BUFFER_SIZE) {														// Set buffer_size
		buffer = (unsigned char *) malloc(filesize * sizeof(char));
		buf_size = filesize;
	} else {
		buffer = (unsigned char *) malloc(BUFFER_SIZE * sizeof(char));
		buf_size = BUFFER_SIZE;
	}
	
	fp = fopen((const char *)filename, "wb");															// Open file for writing
	if (!fp) {
		perror("save_file()");
		exit(1);
	}
	bytes_read = 0;											
	size_left = filesize;
	if (!server)
		printProgress(0.0);
	do{
		if (size_left >= buf_size)														// Read buffer in buffer_size pieces and write to file
			recv_size = buf_size;
		else
			recv_size = size_left;

		ret = recvn(ssl, buffer, recv_size, 0);
		if (ret == -1){
			perror("reading...");
			exit(1);
		}
		if (ret == 0 && filesize != 0)
			perror("save_file()");
		else{
			fwrite(buffer, ret, 1, fp);
			bytes_read += ret;
			size_left -= ret;
			if (!server)
				printProgress((double)bytes_read/filesize);
		}
	} while (bytes_read < filesize);
	if (!server)
		printf("\n");
	free(buffer);
	fclose(fp);
}

																						// Converts time elapsed from seconds into string of form (hh mm ss)
void time_elapsed(double seconds, char *timestr) {
																						// Calculate hours, minutes and seconds
	int h = ((int)seconds/3600); 
	int m = ((int)seconds -(3600*h))/60;
	int s = ((int)seconds -(3600*h)-(m*60));
																						// Convert integers to string using sprintf
	char hr[10];
	char min[3];
	char sec[3];
	sprintf(hr, "%d", h);
	strcat(hr, "\0");
	sprintf(min, "%d", m);
	strcat(min, "\0");
	sprintf(sec, "%d", (int)s);
	strcat(sec, "\0");

	if (h == 0) {																		// Only show hours and minutes if they are non zero
		if (m == 0) {
			strcpy(timestr, sec);
			strcat(timestr, "s");

		} else {
			strcpy(timestr, min);
			strcat(timestr, "m ");
			strcat(timestr, sec);
			strcat(timestr, "s");
		}
	} else {
		strcpy(timestr, hr);
		strcat(timestr, "h ");
		strcat(timestr, min);
		strcat(timestr, "m ");
		strcat(timestr, sec);
		strcat(timestr, "s");
	}

}

int init_ctx(SSL_CTX** ctx,SSL_METHOD** method) {  
	OpenSSL_add_all_algorithms();       		// Register all algorithm 
	SSL_library_init(); 						//Load encryption & hashing algorithms for the SSL program 
	SSL_load_error_strings();					// Load the error strings for SSL & CRYPTO APIs 
	*method = (SSL_METHOD*)SSLv23_method();		// Create an SSL_METHOD structure 
	*ctx = SSL_CTX_new(*method);				// Create an SSL_CTX structure */
	if (*ctx == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}
    return 1;
}

int verify_certificate(X509* server_cert) {
  char* str; 
  if (server_cert != NULL) {
		str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
		if (str == NULL) {
			fprintf(stderr,"The server certificate could not be verified.\n");
			ERR_print_errors_fp(stderr);
			exit(-1);
		}
		free (str);
		str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
		if (str == NULL) {
			fprintf(stderr,"The server certificate could not be verified.\n");
			ERR_print_errors_fp(stderr);
			exit(-1); 
		}
		free(str);
		X509_free (server_cert);
	} else {
		fprintf(stderr,"The SSL server does not have certificate.\n");
		ERR_print_errors_fp(stderr);
		exit(-1);
	}
}


