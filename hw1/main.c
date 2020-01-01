#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>

struct timespec ts = {0, 10};

//正在執行於哪一顆core上面
int cpu_p0, cpu_p1;

//Peteron's solution所需要的變數
atomic_int turn=0;
atomic_int flag[2] = {0, 0};

//統計現在正有多少個thread在CS中
int in_cs = 0;
//統計每一個thread進入CS的次數
int p1_in_cs = 0;
int p0_in_cs =0;

//每秒鐘印出P0和P1進入CS的次數
void per_second(int signum) {
    static int p0_pre, p1_pre;
    printf("進入次數（每秒）p0: %5d, p1: %5d", p0_in_cs - p0_pre, p1_in_cs - p1_pre);
    printf("，分別執行於 core#%d 及 core#%d\n", cpu_p0, cpu_p1);    
    p0_pre = p0_in_cs;
    p1_pre = p1_in_cs;
    alarm(1);
}

void p0(void) {
    printf("start p0\n");
    while (1) {
		//Peteron's solution的進去部分的程式碼
        //atomic_store(&flag[0], 1);
        atomic_store_explicit(&flag[0],1,memory_order_relaxed); //B
        atomic_thread_fence(memory_order_seq_cst);
        atomic_store_explicit(&turn,1,memory_order_relaxed);
        //atomic_store(&turn, 1);
        while (atomic_load(&flag[1]) && atomic_load(&turn)==1)
                ;   //waiting
        //底下程式碼用於模擬在critical section
        cpu_p0 = sched_getcpu();
        in_cs++;	//計算有多少人在CS中
        nanosleep(&ts, NULL);
        if (in_cs == 2) fprintf(stderr, "p0及p1都在critical section\n");
        p0_in_cs++;	//P0在CS幾次
        nanosleep(&ts, NULL);
        in_cs--;	//計算有多少人在CS中
		//Peteron's solution的離開部分的程式碼
        atomic_store(&flag[0], 0);
    } 
}

void p1(void) {
    printf("start p1\n");
    while (1) {
        //atomic_store(&flag[1], 1);
        atomic_store_explicit(&flag[1],1,memory_order_relaxed);
        atomic_thread_fence(memory_order_seq_cst);
        //atomic_store(&turn, 0);
        atomic_store_explicit(&turn,0,memory_order_relaxed);
        while (atomic_load(&flag[0]) && atomic_load(&turn)==0)
                ;   //waiting
        //底下程式碼用於模擬在critical section
        cpu_p1 = sched_getcpu();
        in_cs++;
        nanosleep(&ts, NULL);
        if (in_cs == 2) fprintf(stderr, "p0及p1都在critical section\n");
        p1_in_cs++;
        nanosleep(&ts, NULL);
        in_cs--;
        //離開critical section
        atomic_store(&flag[1], 0);
    } 
}

int main(void) {
	pthread_t id1, id2;
    alarm(1);
    signal(SIGALRM, per_second);
	pthread_create(&id1,NULL,(void *) p0,NULL);
	pthread_create(&id2,NULL,(void *) p1,NULL);
	pthread_join(id1,NULL);
	pthread_join(id2,NULL);
	return (0);
}