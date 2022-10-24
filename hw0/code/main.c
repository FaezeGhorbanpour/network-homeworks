//In the name of GOD
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>
#include <pthread.h>
#define MAX_STRING_LEN 100000



void *readFunction(void *arg){
	char str[MAX_STRING_LEN];
	int n = *((int *) arg);
	int a = 0;
	do{
		memset(str,0,strlen(str));
		a = recv(n, str, sizeof(str), 0);
		printf("%s",str);
	}while(a != 0 && strlen(str) != 0);
}

void *writeFunction(void *arg){
	char str[MAX_STRING_LEN];
	int n = *((int *) arg),a;
	do{
		memset(str,0,strlen(str));
		a=fgets(str, MAX_STRING_LEN, stdin);
		send(n, str, strlen(str)+1, 0);
	}while(a != 0);
}

int main(int argc, char ** argv)
{
	
	if(argc <= 1) {
		struct sockaddr_in address;
		pthread_t readThread, writeThread;
		int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
		address.sin_family = AF_INET;
		address.sin_addr.s_addr =  INADDR_ANY;
		address.sin_port = htons(1234);
		int a = bind(serverSocket, (struct sockaddr *) &address, sizeof(address));
		listen(serverSocket, 5);
		while(1){
			int n = sizeof(struct sockaddr_in);
			int accepting = accept(serverSocket, (struct sockaddr *) &address, &n);
			pthread_create(&readThread, NULL, readFunction, &accepting);
			pthread_create(&writeThread, NULL, writeFunction, &accepting);
			pthread_join(readThread, NULL);
			pthread_cancel(writeThread);
			close(accepting);
		}
		close(serverSocket);
	}
	else if(argc == 3) {
		struct sockaddr_in address;
		int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
		pthread_t readThread, writeThread;
		address.sin_family = AF_INET;
		address.sin_addr.s_addr = inet_addr(argv[1]);
		address.sin_port = htons( atoi(argv[2]) );
		if (connect(clientSocket, (struct sockaddr *) &address, sizeof(address)) <0 )
			printf("CAN'T CONNECT");
		else {
			pthread_create(&readThread, NULL, readFunction,  &clientSocket);
			pthread_create(&writeThread, NULL, writeFunction, &clientSocket);
			pthread_join(writeThread, NULL);
			pthread_cancel(readThread);
		}
		close(clientSocket);
	}
	else {
		printf("Unknown argument");
	}
	return 0;
}
