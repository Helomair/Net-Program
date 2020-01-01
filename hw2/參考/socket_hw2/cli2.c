
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

int sockfd;//客户端socket
int filefd;
char* IP = "192.168.10.143";//服务器的IP
short PORT = 10222;//服务器服务端口
typedef struct sockaddr SA;
char name[30];

void init(){
    sockfd = socket(PF_INET,SOCK_STREAM,0);
    struct sockaddr_in addr;
    addr.sin_family = PF_INET;
    addr.sin_port = htons(PORT);
    //addr.sin_addr.s_addr = inet_addr(IP);
    addr.sin_addr.s_addr=htonl(INADDR_ANY);
    
    if (connect(sockfd,(SA*)&addr,sizeof(addr)) == -1){
        perror("無法連接");
        exit(-1);
    }
    printf("[INFO] Client start Successfully !\n");
}


void start(){

    char buf2[100] = {};
    // sprintf(buf2,"%s 進入了聊天室",name);
    // send(sockfd,buf2,strlen(buf2),0);
    // memset(buf2, '\0', sizeof(buf2));

    while(1){
        recv(sockfd,buf2,sizeof(buf2),0);
        if (strcmp(buf2,"server-req-name?") == 0){
            send(sockfd,name,strlen(name),0);
            break;
        }
    }


    pthread_t id;
    void* recv_thread(void*);
    pthread_create(&id,0,recv_thread,0);
    
    while(1){
        char buf[100] = {};
        fgets(buf, sizeof(buf), stdin);
        char *ptr = strstr(buf, "\n");
        *ptr = '\0';
        char msg[131] = {};
        if (strcmp(buf,"bye") == 0){
            memset(buf2,0,sizeof(buf2));
            sprintf(buf2,"[INFO] %s 退出了聊天室",name);
            send(sockfd,buf2,strlen(buf2),0);
            break;
        }
        if (strcmp(buf,"ls") == 0){
            memset(buf2,0,sizeof(buf2));
            sprintf(buf2,"ls");
            send(sockfd,buf2,strlen(buf2),0);
        }
        else{
            sprintf(msg,"%s:%s",name,buf);
            send(sockfd,msg,strlen(msg),0);
        }
    }
    close(sockfd);
}

void* recv_thread(void* p){
    while(1){
        char buf[100] = {};
        if (recv(sockfd,buf,sizeof(buf),0) <= 0){
            return;
        }
        if (strcmp(buf,"server-req-name ?") == 0){
            send(sockfd,name,strlen(name),0);
        }
        else{
            printf("%s\n",buf);
        }
    }
}

int main(){
    init();
    printf("[INFO] 請輸入帳號：");
    scanf("%s",name);
    start();
    return 0;
}
