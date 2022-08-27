#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> 
//socket
#include <sys/types.h>
#include <sys/socket.h>    
#include <netinet/in.h>
#include <arpa/inet.h>
//pthread
#include <pthread.h> 

#define LOGD(fmt, ...)  printf(fmt, ##__VA_ARGS__) 

#define SERVER_PORT 43999

static int server_status = 0;

static void* cli_loop(void *argv)
{
    int cli_fd = *(int*)argv;
    unsigned char buffer[512];
    int err_cnt;
    int buffer_len;
    
    LOGD("client thread enter,fd = %d\n", cli_fd);
    
    err_cnt = 0;
    int recv_count = 0;
    while(1)
    {
        buffer_len = recv(cli_fd,buffer,sizeof(buffer),0);
        if(buffer_len <= 0)
        {
            if(err_cnt == 10)
                break;
            usleep(100*1000);
            err_cnt++;
            continue;
        }
        LOGD("recv a packet, %d\n", recv_count);
        recv_count++;
        err_cnt = 0;
    }    
    shutdown(cli_fd,SHUT_RDWR);    
    
    LOGD("client thread exit,fd = %d\n", cli_fd);
    return 0;
}

static void* serv_listen_loop(void *argv)
{
    int serv_fd, cli_fd;
    socklen_t cli_addr_size;
    struct sockaddr_in serv_addr, cli_addr;
    pthread_t cli_tid;
    struct client_info *cli_info;
    
    LOGD("serv_listen_loop enter\n");
    serv_fd = socket(PF_INET,SOCK_STREAM,0);
    if(serv_fd < 0)
    {
        LOGD("socket port:%d create failed\n", SERVER_PORT);
        return 0;
    }

    memset(&serv_addr,0,sizeof(serv_addr));    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    bind(serv_fd,(struct sockaddr*)&serv_addr,sizeof(serv_addr));
    listen(serv_fd,1);
    
    server_status = 1;
    while(1)
    {
        cli_addr_size = sizeof(struct sockaddr_in);
        cli_fd = accept(serv_fd,(struct sockaddr*)&cli_addr,&cli_addr_size);
        if(cli_fd > 0)
        {
            LOGD("accept one client, fd = %d\n",cli_fd);
            if(!pthread_create(&cli_tid, NULL, cli_loop, (void*)&cli_fd))
            {
                LOGD("create client thread successful\n");
            }else
            {
                LOGD("create client thread failed\n");
            }
        }        
    }
    LOGD("serv_listen_loop exit\n");
    return 0;
}

static int create_cmd_serv()
{
    pthread_t serv_tid;
    
    if(!pthread_create(&serv_tid, NULL, serv_listen_loop, NULL))
    {
        LOGD("create server listen thread successful\n");
    }else
    {
        LOGD("create server listen thread failed\n");
        return 0;
    }
    
    return 1;    
}

static int connect_serv(int port)
{
    int cli_fd;
    struct sockaddr_in serv_addr, cli_addr;
    
    memset(&serv_addr,0,sizeof(serv_addr));    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    
    cli_fd = socket(PF_INET,SOCK_STREAM,0);    
    
    if(connect(cli_fd,(struct sockaddr*)&serv_addr,sizeof(serv_addr)))
    {
        LOGD("connect failed\n");
        exit(0);
    }
    LOGD("connect successful\n");
    
    return cli_fd;
}

int main()
{
    if(create_cmd_serv() == 0)
    {
        return 0;
    }
    while(server_status != 1)
    {
        usleep(100*1000);
    }
    int client_fd = connect_serv(SERVER_PORT);
    
    const char send_buf[] = "hello";
    while(1)
    {
        send(client_fd,send_buf,sizeof(send_buf),0);
        usleep(1000*1000);
    }
    
    
    return 0;
}
