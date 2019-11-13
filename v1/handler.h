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

void handle_socket(int);
void get_index(int);
void get_img(int);
void post_upload(int, char*);
char* __get_file_name_and_skip_header(const char*, char*);
