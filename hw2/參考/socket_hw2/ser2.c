#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

int sockfd;//服务器socket
int fds[100];//客户端的socketfd,100个元素，fds[0]~fds[99]
int size =100 ;//用来控制进入聊天室的人数为100以内
char* IP = "192.168.10.143";
short PORT = 10222;
typedef struct sockaddr SA;
char* account[105];

void init(){
    sockfd = socket(PF_INET,SOCK_STREAM,0);
    if (sockfd == -1){
        perror("Create socket Failed");
        exit(-1);
    }
    struct sockaddr_in addr;
    addr.sin_family = PF_INET;
    addr.sin_port = htons(PORT);
    //addr.sin_addr.s_addr = inet_addr(IP);
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    
    if (bind(sockfd,(SA*)&addr,sizeof(addr)) == -1){
        perror("Bind Failed");
        exit(-1);
    }
    if (listen(sockfd,100) == -1){
        perror("Listen Failed");
        exit(-1);
    }

    for(int i=0; i<105; i++)
        account[i] = (char *)malloc(sizeof(char)*11);
}

void SendMsgToAll(char* msg){
    int i;
    for (i = 0;i < size;i++){
        if (fds[i] != 0){
            printf("System sending to %d\n",fds[i]);
            send(fds[i],msg,strlen(msg),0);
        }
    }
}

void getAlluser(int fd){

    printf("%d want all user info 030.\n", fd);
    send(fd,"now, these people are online ... \n",strlen("now, these people are online ... \n"),0);
    for (int i = 0;i < size;i++){
        // 找一下誰的 fd == 戶口名簿的總列表
        if (fds[i] != 0){
            char buf[100] = {};

            sprintf(buf, "%s : %d " ,account[fds[i]], fds[i] );
            send(fd,buf,strlen(buf),0);
        }
    }
}


void* service_thread(void* p){
    int fd = *(int*)p;
    printf("pthread = %d\n",fd);

    char buf[100] = {};

    send(fd ,"server-req-name?",strlen("server-req-name?"),0);
    recv(fd,buf,sizeof(buf),0);



    strcpy(account[fd], buf);
    account[fd][strlen(account[fd])] = '\0';
    printf("New account : %s\n",  buf);
    SendMsgToAll( strcat(buf, " enter the room !") );

    while(1){
        char buf2[100] = {};

        if (recv(fd,buf2,sizeof(buf2),0) <= 0){
            // 對方關閉了
            int i;
            for (i = 0;i < size;i++){
                if (fd == fds[i]){
                    fds[i] = 0; // 88
                    break;
                }
            }
            printf("退出：fd = %dquit\n",fd);
            pthread_exit((void*)i);
        }

        if (strcmp(buf2,"ls") == 0){
            getAlluser(fd);
        }else if( strstr(buf2, "-p") ){
            char *ptr = buf2; int idx = 0;
            char *msg = (char*)malloc( 256*sizeof(char) );
            while(*ptr!='-'){
                msg[idx++] = *ptr++;
            }
            msg[idx] = '\0';
            int receiver = atoi(ptr+3);
            printf("receiver : %d\n", receiver);
            send(receiver,msg,strlen(msg),0);

        }
        else{
            SendMsgToAll(buf2);
        }
        memset(buf2,0,sizeof(buf2));

    }
}

void service(){
    printf("Server Start !\n");
    while(1){
        struct sockaddr_in fromaddr;
        socklen_t len = sizeof(fromaddr);
        int fd = accept(sockfd,(SA*)&fromaddr,&len);
        if (fd == -1){
            printf("Client occurr Error ...\n");
            continue;
        }
        int i = 0;
        for (i = 0;i < size;i++){
            if (fds[i] == 0){
                fds[i] = fd;
                printf("fd = %d\n",fd);
                pthread_t tid;
                pthread_create(&tid,0,service_thread,&fd);
                break;
            }
            if (size == i){
                char* str = "Sorry, the room is full !";
                send(fd,str,strlen(str),0); 
                close(fd);
            }
        }
    }
}

int main(){
    init();
    service();
}
