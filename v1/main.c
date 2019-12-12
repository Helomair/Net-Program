#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "handler.h"
// fix on mac
#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

int main(int argc, char** argv)
{
    int i, pid, listenfd, socketfd;
    size_t length;
    static struct sockaddr_in cli_addr;
    static struct sockaddr_in serv_addr;

    /* 背景繼續執行 */
    //if (fork() != 0)
     //   return 0;

    /* 讓父行程不必等待子行程結束 */
    signal(SIGCLD, SIG_IGN);

    /* 開啟網路 Socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        exit(3);

    /* 網路連線設定 */
    serv_addr.sin_family = AF_INET;
    /* 使用任何在本機的對外 IP */
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    /* 使用 80 Port */
    serv_addr.sin_port = htons(8080);

    /* 開啟網路監聽器 */
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        exit(3);

    /* 開始監聽網路 */
    if (listen(listenfd, 64) < 0)
        exit(3);

    while (1) {
        length = sizeof(cli_addr);
        /* 等待客戶端連線 */

        if ((socketfd = accept(listenfd, (struct sockaddr*)&cli_addr, &length)) < 0)
            exit(3);

        /* 分出子行程處理要求 */
        if ((pid = fork()) < 0) {
            exit(3);
        } else {
            if (pid == 0) { /* 子行程 */
                close(listenfd);
                handle_socket(socketfd);
            } 
            else { /* 父行程 */
                close(socketfd);
            }
        }
    }
}
