CC = g++

ifeq ($(OSTYPE), solaris)
	CFALGS= -Wall -gm64
	LIB = -lsocket -lnsl -lpthread -lcrypto -lssl
else
	CFALGS= -Wall -g -O2
	LIB = -lpthread -lcrypto -lssl
endif

all: myftpserver myftpclient

myftpserver: myftpserver.o myftp.o
	${CC} ${CFLAGS} -o myftpserver myftpserver.o myftp.o ${LIB}

myftpclient: myftpclient.o myftp.o
	${CC} ${CFALGS} -o myftpclient myftpclient.o myftp.o ${LIB}

myftpserver.o: myftpserver.c 
	${CC}$ ${CFLAGS} -c myftpserver.c 

myftpclient.o: myftpclient.c
	${CC}$ ${CFLAGS} -c myftpclient.c 

myftp.o: myftp.c
	${CC} ${CFLAGS} -c myftp.c 

clean:
	${RM} *.o

cleanall: clean
	${RM} myftpclient myftpserver
	
