#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "stdbool.h"
#include "sys/socket.h"
#include "sys/types.h"
#include "netdb.h"
#include "netinet/in.h"
#include "pthread.h"
#include "errno.h"

#define MESSAGE_BUFFER 500
#define USERNAME_BUFFER 10

typedef struct {
	char* prompt;
    	int socket;
} thread_data;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
// Connect to server
void * connect_to_server(int socket_fd, struct sockaddr_in *address)
{
    	int response = connect(socket_fd, (struct sockaddr *) address, sizeof *address);
    	if (response < 0)
	{
        	fprintf(stderr, "connect() failed: %s\n", strerror(errno));
        	exit(1);
    	} else
      		printf("Connected\n");
}

// Get message from stdin and send to server
void * send_message(char prompt[USERNAME_BUFFER+4], int socket_fd, struct sockaddr_in *address,char username[])
{
//  	printf("%s", prompt);
  	char message[MESSAGE_BUFFER];
	char buff[MESSAGE_BUFFER];
	char notice[]="/send";
	FILE *fp;
	memset(message,NULL,sizeof(message));
	memset(buff,NULL,sizeof(buff));

	send(socket_fd,username,strlen(username),0);
  	while (fgets(message, MESSAGE_BUFFER, stdin) != NULL)
	{
		printf("%s",prompt);
      		if (strncmp(message, "/quit", 5) == 0)
		{
        		printf("Closing connection...\n");
        		exit(0);
      		}
/*
		else if(strncmp(message, "/send", 5) == 0)
		{
			//notice server thar client want to send a file
			send(socket_fd,message,strlen(message),0);
			fp=fopen("./send/send.txt","r");
			fscanf(fp,"%s",buff);
			fclose(fp);
			send(socket_fd,buff,strlen(buff),0);
		}
*/
			send(socket_fd, message, strlen(message), 0);
			memset(message,NULL,sizeof(message));
  	}
}

void * receive(void * threadData)
{
    	int socket_fd, response;
    	char message[MESSAGE_BUFFER];
    	thread_data* pData = (thread_data*)threadData;
    	socket_fd = pData->socket;
    	char* prompt = pData->prompt;
	char catch[]="<SERVER> catch";		//for file sending
	char confirm[]="<SERVER> confirm";	//for file sending
	char ok[]="ok";				//for file sending
	char buff[MESSAGE_BUFFER];
	char buff2[2];
	FILE *fp;

    	// Print received message
   	while(true)
	{
		memset(message,NULL,MESSAGE_BUFFER);//clear message buffer
		memset(buff,NULL,sizeof(buff));
		fflush(stdout);
        	response = recv(socket_fd, message, MESSAGE_BUFFER, 0);
        	if (response == -1)
		{
          		fprintf(stderr, "recv() failed: %s\n", strerror(errno));
          		break;
        	}
		else if (response == 0)
		{
              		printf("\nPeer disconnected\n");
              		break;
        	}

		if(strcmp(message,confirm)==0)
		{
			fp=fopen("./send/send.txt","r");
			//fscanf(fp,"%s",buff);
			fgets(buff,MESSAGE_BUFFER,fp);
			fclose(fp);
			send(socket_fd,buff,strlen(buff),0);
		}
		else if(strncmp(message,catch,12)==0)
		{
			send(socket_fd,ok,2,0);//notice server
			fp=fopen("./receive/receive.txt","w");
			pthread_mutex_lock(&mutex);
			recv(socket_fd,buff,MESSAGE_BUFFER,0);
			pthread_mutex_unlock(&mutex);
			fprintf(fp,"%s",buff);
			fclose(fp);
		}
		else
		{
              		printf("%s", message);
              		printf("%s", prompt);
              		fflush(stdout); // Make sure "User>" gets printed
          	}
    	}
}

int main(int argc, char**argv)
{
    	long port = strtol(argv[2], NULL, 10);
    	struct sockaddr_in address, cl_addr;
    	char * server_address;
    	int socket_fd, response;
    	char prompt[USERNAME_BUFFER+4];
   	char username[USERNAME_BUFFER];
    	pthread_t thread;

    	// Check for required arguments
    	if (argc < 3)
	{
        	printf("Usage: client ip_address port_number\n");
        	exit(1);
    	}

    	// Get user handle
    	printf("Enter your user name: ");
    	fgets(username, USERNAME_BUFFER, stdin);
    	username[strlen(username) - 1] = 0; // Remove newline char from end of string
    	strcpy(prompt, username);
    	strcat(prompt, "> ");

    	server_address = argv[1];
    	address.sin_family = AF_INET;
    	address.sin_addr.s_addr = inet_addr(server_address);
    	address.sin_port = htons(port);
    	socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    	connect_to_server(socket_fd, &address);

    	// Create data struct for new thread
    	thread_data data;
    	data.prompt = prompt;
    	data.socket = socket_fd;

    	// Create new thread to receive messages
    	pthread_create(&thread, NULL, receive, (void *) &data);

    	// Send message
    	send_message(prompt, socket_fd, &address,username);

    	// Close socket and kill thread
    	close(socket_fd);
    	pthread_exit(NULL);
    	return 0;
}
