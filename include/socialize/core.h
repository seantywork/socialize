#ifndef _SOCIALIZE_CORE_H_
#define _SOCIALIZE_CORE_H_



#include <stdio.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>  
#include <unistd.h> 
#include <time.h>
#include <endian.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/time.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h> 

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#include "mongoose/mongoose.h"
#include "cJSON/cJSON.h"

#define DEBUG_THIS 0

#define HUB_WORD           8
#define HUB_HEADER_BYTELEN HUB_WORD * 3
#define HUB_BODY_BYTELEN   HUB_WORD * 1
#define HUB_BODY_BYTEMAX   HUB_WORD * 1280 //10KB
#define HUB_TIMEOUT_MS 5000

#define HUB_HEADER_AUTHSOCK "AUTHSOCK"
#define HUB_HEADER_REGSOCK_CREATE "REGSOCK_CREATE"
#define HUB_HEADER_REGSOCK_JOIN "REGSOCK_JOIN"


#define HUB_HEADER_AUTHFRONT "AUTHFRONT"
#define HUB_HEADER_AUTHFRANK "AUTHFRANK"
#define HUB_HEADER_SENDSOCK "SENDSOCK"
#define HUB_HEADER_RECVSOCK "RECVSOCK"
#define HUB_HEADER_SENDFRONT "SENDFRONT"
#define HUB_HEADER_RECVFRONT "RECVFRONT"
#define HUB_HEADER_SENDFRANK "SENDFRANK"
#define HUB_HEADER_RECVFRANK "RECVFRANK"



#define TRUE 1
#define FALSE 0
#define MAX_BUFF HUB_BODY_BYTEMAX
#define MAX_CONN 80
#define MAX_ID_LEN 1024
#define MAX_PW_LEN 4096
#define PORT_FRONT 3000
#define PORT_SOCK 3001 


#define ISSOCK 1
#define ISFRONT 2
#define CHAN_ISSOCK 3
#define CHAN_ISFRONT 4



#define MAX_DEVICE_NAME 40
#define MAX_EVENTS_NO 400
#define MAX_EVENT_TEXT_SIZE 10
#define EVENTS_PER_PAGE 20

#define MAX_USER_NAME 1024
#define MAX_USER_PASS 2048
#define MAX_USER_ACCESS_TOKEN 1024

#define MAX_COOKIE_LEN 1024
#define MAX_COOKIE_KEYLEN 32

#define MAX_USERS 10

#define MAX_PUBLIC_URI_LEN 512

#define MAX_REQUEST_URI_LEN 1024 * 10
#define MAX_CLIENT_ID_LEN 1024
#define MAX_CLIENT_SECRET_LEN 1024
#define MAX_POST_FIELDS_LEN 1024 * 10

#define MAX_CODELEN 256
#define GOAUTH_TOKENLEN 512

#define MAX_REST_BUFF 1024 * 10
#define MAX_WS_BUFF 1024 * 10

#define WS_MAX_COMMAND_LEN 32
#define WS_MAX_COMMAND_DATA_LEN WS_MAX_COMMAND_LEN * 8
#define WS_MAX_COMMAND_RECV_LEN WS_MAX_COMMAND_LEN * 8 * 8

#define WS_COMMAND_REQ_KEY "reqkey"
#define WS_COMMAND_ROUNDTRIP "roundtrip"

#define WS_COMMAND_GENCERT "gencert"

#define DEFAULT_RANDLEN 64



#ifndef HTTP_URL
#define HTTP_URL "http://0.0.0.0:3000"
#endif


#ifndef HTTPS_URL
#define HTTPS_URL "https://0.0.0.0:3443"
#endif

#define FRONT_WEB_ROOT "public"

#define IS_BIG_ENDIAN (!*(unsigned char *)&(uint16_t){1})

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

#ifndef SERVER_KEY
# define SERVER_KEY "tls/server_priv.pem"
#endif

#ifndef SERVER_CERT
# define SERVER_CERT "tls/server.crt.pem"
#endif

#define HUB_CA_NAME "socializeca"

#ifndef HUB_CA_CERT
# define HUB_CA_CERT "tls/ca.crt.pem"
#endif

#ifndef HUB_CA_PRIV
# define HUB_CA_PRIV "tls/ca_priv.pem"
#endif

#ifndef HUB_CA_PUB
# define HUB_CA_PUB "tls/ca_pub.pem"
#endif


#ifndef SUB1_CERT
# define SUB1_CERT "tls/sub1.crt.pem"
#endif


#ifndef SUB2_CERT
# define SUB2_CERT "tls/sub2.crt.pem"
#endif


#define DEFAULT_RANDLEN 64
//#define WAIT 7   





struct user {
    char name[MAX_USER_NAME];
    char pass[MAX_USER_PASS];
    int auth;
    uint8_t token[MAX_PW_LEN];
    int cid;
};


struct CHANNEL_CONTEXT {
    int allocated;
    int sockfd;
    int frontfd;
    char id[MAX_ID_LEN];
    char pw[MAX_PW_LEN];
    SSL *ssl;
    SSL_CTX *ctx;
    int fd_ptr;
    int fds[MAX_CONN];

};

struct SOCK_CONTEXT {
    int allocated;
    int sockfd;
    SSL *ssl;
    SSL_CTX *ctx;
    int auth;
    char id[MAX_ID_LEN];
    int chan_idx;
    pthread_mutex_t lock;
    struct SOCK_CONTEXT *next;
};




struct HUB_PACKET {

    int ctx_type;
    char id[MAX_ID_LEN];
    int fd;
    uint8_t header[HUB_HEADER_BYTELEN];
    uint64_t body_len;
    uint8_t wbuff[MAX_BUFF];
    uint8_t* rbuff;

    int flag;

};

struct settings {
    bool log_enabled;
    int log_level;
    long brightness;
    char *device_name;
  };



extern char CA_CERT[MAX_PW_LEN];

extern char CA_PRIV[MAX_PW_LEN];

extern char CA_PUB[MAX_PW_LEN];


extern int s_sig_num;


extern struct settings s_settings;

extern uint64_t s_boot_timestamp; 

extern char *s_json_header;

extern struct mg_mgr mgr;

extern struct user USER;

extern struct CHANNEL_CONTEXT CHAN_CTX[MAX_CONN];

extern struct SOCK_CONTEXT SOCK_CTX[MAX_CONN];



extern FILE* LOGFP;
extern pthread_mutex_t G_MTX;

extern int SOCK_FD;
extern int SOCK_SERVLEN;
extern int SOCK_EPLFD;
extern struct epoll_event SOCK_EVENT;
extern struct epoll_event *SOCK_EVENTARRAY;


extern int FRONT_FD;
extern int FRONT_SERVLEN;
extern int FRONT_EPLFD;
extern struct epoll_event FRONT_EVENT;
extern struct epoll_event *FRONT_EVENTARRAY;

extern int MAX_SD;

extern int OPT;



#endif