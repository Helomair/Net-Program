#include<time.h>
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
#include<pthread.h>
 
#define LISTENQ 5
#define MAXLINE 512
#define MAXMEM 10
#define NAMELEN 20
 
int listenfd,connfd[MAXMEM];//分别紀錄server端的file descriptor與連接的多個client端的file descriptor
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
char user[MAXMEM][NAMELEN];
void quit();//server close
void rcv_snd(int n);//server接受訊息轉發給其他client
 
int main()
{
    	pthread_t thread;
	struct sockaddr_in servaddr,cliaddr;
    	socklen_t len;
    	char buff[MAXLINE];
 
	//使用socket創建server的fd
//	printf("Socket...\n");
    	listenfd=socket(AF_INET,SOCK_STREAM,0);
   	if(listenfd<0)
    	{
        	printf("Socket created failed.\n");
        	return -1;
    	}

	//使用bind將server的fd和port綁定
//    	printf("Bind...\n");
    	servaddr.sin_family=AF_INET;
	servaddr.sin_port=htons(6666);
    	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);

    	if(bind(listenfd,(struct sockaddr*)&servaddr,sizeof(servaddr))<0)
    	{
        	printf("Bind failed.\n");
        	return -1;
    	}

	//使用listen讓server開始監聽client
    	printf("listening...\n");
    	listen(listenfd,LISTENQ);

	//建立一個thread對server進行管理（關閉）
    	pthread_create(&thread,NULL,(void*)(&quit),NULL);
 
	//紀錄閒置的client空間（-1為空閒)
	//initialize
    	int i=0;
    	for(i=0;i<MAXMEM;i++)
       		connfd[i]=-1;
 	memset(user,NULL,sizeof(user));
	printf("initializing.....\n");
    	while(1)
    	{
        	len=sizeof(cliaddr);
       		for(i=0;i<MAXMEM;i++)
            		if(connfd[i]==-1)
                		break;
		printf("receiving....\n");
		//使用accept從listen接收的要求連線的queue中取得一個client
        	connfd[i]=accept(listenfd,(struct sockaddr*)&cliaddr,&len);
		
		//針對當前的client創造一個thread，對這個client進行訊息處理
        	pthread_create(malloc(sizeof(pthread_t)),NULL,(void*)(&rcv_snd),(void*)i);
 
    	}
    	return 0;
}
 
void quit()
{
    	char msg[10];
    	while(1)
    	{
       		scanf("%s",msg);
        	if(strcmp("/quit",msg)==0)
        	{
            		printf("Byebye...\n");
            		close(listenfd);
            		exit(0);
        	}
    	}
}
 
void rcv_snd(int n)
{
    	char buff[MAXLINE];
    	char buff1[MAXLINE];
    	char buff2[MAXLINE];
    	char name[NAMELEN];

	char temp[]="<SERVER> Whom U want to send ? ";		//for private chat
	char temp2[]="<SERVER> Context ? ";			//for private chat
	char temp3[]="<SERVER> Wait... ";			//for file sending
	char temp4[]="<SERVER> File has been sending.";		//for file sending
	char temp5[]="<SERVER> Receiver refuse to receive.";	//for file sending
	char temp6[]="<SERVER> catch";				//for file sneding
	char temp7[]="<SERVER> confirm";			//for file sending
	char temp8[]="ok";
	char check[1];
	char ok[3];
	char message[MAXLINE];
    	int i=0;
    	int retval;

	//獲得這個thread相對應的client的用戶名
    	int len;
    	len=recv(connfd[n],name,NAMELEN,0);
     	if(len>0)
	{
        	name[len]=0;
		strcpy(user[n],name);
	}
	//把新加入的client告知所有client
	memset(buff,NULL,sizeof(buff));
    	strcpy(buff,name);
    	strcat(buff,"\tjoin in\n");
    	for(i=0;i<MAXMEM;i++)
        	if(connfd[i]!=-1)
            		send(connfd[i],buff,strlen(buff),0);
	//接受當前client的訊息並轉發給client
    	while(1)
    	{
		memset(buff,NULL,sizeof(buff));
		memset(buff1,NULL,sizeof(buff1));
		memset(buff2,NULL,sizeof(buff2));
		memset(message,NULL,sizeof(message));
		memset(check,NULL,sizeof(check));
        	if((len=recv(connfd[n],buff1,MAXLINE,0))>0)
        	{
            		buff1[len]=0;
 
			//當current client輸入的訊息為"/quit"時，current client logs out
             		if(strcmp("/quit",buff1)==0)
             		{
                 		close(connfd[n]);
                 		connfd[n]=-1;
                 		pthread_exit(&retval);
             		}
			//private chat
 			else if(strncmp("/chat",buff1,5)==0)
			{
				printf("private message sending....\n");
				send(connfd[n],temp,strlen(temp),0);
				len=recv(connfd[n],buff2,MAXLINE,0);	//被傳送訊息對象的名字
				buff2[len]=0;
				send(connfd[n],temp2,strlen(temp2),0);
				len=recv(connfd[n],message,MAXLINE,0);
				message[len]=0;
			
				strcpy(buff,name);
				strcat(buff,": ");
				strcat(buff,message);
				
				for(i=0;i<MAXMEM;i++)
				{
					if(connfd[i]!=-1)
					{
						if(strncmp(buff2,user[i],strlen(buff2)-1)==0)
							send(connfd[i],buff,strlen(buff),0);
						else
							continue;
					}
				}
			}
			//file transfer
			else if(strncmp("/send",buff1,5)==0)
			{
				printf("file needs to be sending....\n");
				pthread_mutex_lock(&mutex);
				send(connfd[n],temp,strlen(temp),0);
				pthread_mutex_unlock(&mutex);
				len=recv(connfd[n],buff2,MAXLINE,0);	//被傳送對象的名字
				buff2[len]=0;
				printf("%s\n",buff2);

//				pthread_mutex_lock(&mutex);		
				send(connfd[n],temp7,strlen(temp7),0);	//notice sender that server is ready to take the message
//				printf("confirm\n");
//				pthread_mutex_unlock(&mutex);

//				pthread_mutex_lock(&mutex);
				recv(connfd[n],message,MAXLINE,0);
//				message[len]=0;
				printf("receive\n");
//				pthread_mutex_unlock(&mutex);
/*
				pthread_mutex_lock(&mutex);
				send(connfd[n],temp3,strlen(temp3),0);
				pthread_mutex_unlock(&mutex);
*/				
				strcpy(buff,"<SERVER> ");
				strcat(buff,name);
				strcat(buff," want to send you a file. Receive it or not ? (Y/y)es or (N/n)o.");

				for(i=0;i<MAXMEM;i++)
				{
					if(connfd[i]!=-1)
					{
						if(strncmp(buff2,user[i],strlen(buff2)-1)==0)
						{
							printf("yes\n");

							pthread_mutex_lock(&mutex);
							send(connfd[i],buff,strlen(buff),0);
							pthread_mutex_unlock(&mutex);

							len=recv(connfd[i],check,1,0);
							check[len]=0;
							if(strncmp(check,"Y",strlen(check)-1)==0 || strncmp(check,"y",strlen(check)-1)==0)
							{
								printf("hee\n");

								pthread_mutex_lock(&mutex);
								send(connfd[i],temp6,strlen(temp6),0);	//notice receiver
								pthread_mutex_unlock(&mutex);
								
								
								len=recv(connfd[i],ok,strlen(ok),0);
								ok[len]=0;
								if(strcmp(ok,temp8)==0)
									send(connfd[i],message,strlen(message),0);
								

								send(connfd[n],temp4,strlen(temp4),0);	//notice sender
							}
							else if(strncmp(check,"N",strlen(check)-1)==0 || strncmp(check,"n",strlen(check)-1)==0)
							{
								send(connfd[n],temp5,strlen(temp5),0);
								memset(message,NULL,sizeof(message));
							}
							else
								continue;
						}
						else
							continue;
					}
				}

			}
			else if(strncmp("/list",buff1,5)==0)
			{
				strcpy(buff,"<SERVER> On line member :");
				for(i=0;i<MAXMEM;i++)
				{
					if(connfd[i]!=-1)
					{
						strcat(buff,user[i]);
						strcat(buff," ");
					}
				}
				strcat(buff,"\n");
				send(connfd[n],buff,strlen(buff),0);
			}
			else
			{
             			strcpy(buff,name);
             			strcat(buff,": ");
             			strcat(buff,buff1);
 
            			for(i=0;i<MAXMEM;i++)
				{
                 			if(connfd[i]!=-1)
					{
						if(strcmp(name,user[i])==0)
							continue;
						else
                      					send(connfd[i],buff,strlen(buff),0);
					}
				}
			}
        	}
    	}
}
