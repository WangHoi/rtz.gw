#pragma once
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

int set_tcp_nodelay(int fd, int nodelay);
int set_tcp_notsent_lowat(int fd, int bytes);
int get_tcp_notsent_lowat(int fd);
int set_socket_max_pacing_rate(int fd, int rate);
int set_socket_keepalive(int fd, int keepalive);
int set_socket_reuseport(int fd, int reuse);
int set_nonblock(int fd, int nonblock);
int set_cloexec(int fd, int cloexec);
int get_socket_error(int fd);
int set_socket_send_buf_size(int fd, int size);
int get_socket_send_buf_size(int fd, int *size);
int set_socket_recv_buf_size(int fd, int size);
int set_ip_tos(int fd, int dscp_class);
