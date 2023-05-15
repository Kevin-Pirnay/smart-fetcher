
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h> //compile with adding -lssl -lcrypto
#include <openssl/err.h>
#include "../storage/storage.h"
#include "fetch.h"

#define STDIN_PATH "/data/proc/std/in/stdin"
#define STDERR_PATH "/data/proc/std/err/stderr"
#define HOSTS_INFOS_INDEX "/data/etc/hosts/index.bin"
#define HOSTS_INFOS_STORAGE "/data/etc/hosts/storage.bin"
#define HOSTS_INFOS_TABLE "/data/etc/hosts/table.txt"
#define HOST_INFOS_STRUCT_FORMAT "sssiii"
#define PORT 443
#define PORT_S "443"
#define TRY_IPV6 0

FILE *STDERR = NULL;

void init_stderr()
{
    STDERR = fopen(STDERR_PATH, "a");

    if(STDERR == NULL) { printf("Unable to open stderr file %s, initialisation failed...\n", STDERR_PATH); exit(1); }
}

void print_error_message(char *message, char *context)
{
    printf("error: %s\ncontext: %s\n", message, context);
    fprintf( STDERR, "error: %s\ncontext: %s\n", message, context);
}

struct Host_infos
{
    char *ip;
    char *canonname;
    char *domain;
    int *family;
    int *protocol;
    int *socket_type;
};

void free_Host_infos(struct Host_infos *ptr)
{
    free(ptr->ip);
    free(ptr->family);
    free(ptr->protocol);
    free(ptr->socket_type);
    free(ptr->canonname);
    free(ptr->domain);
    free(ptr);
}

struct Host_infos *search_for_host_informations(char *domain)
{
    struct Host_infos *infos = (struct Host_infos *)deserialize(HOSTS_INFOS_INDEX, HOSTS_INFOS_STORAGE, domain);

    if(infos == NULL) print_error_message("domain doens't match any data stored. Call dns requested...", domain);

    return infos;
}

void call_dns_to_get_address_infos(const char *domain, struct addrinfo **response_dns)
{
    int error = getaddrinfo(domain,PORT_S,NULL, response_dns);

    if (error != 0) 
    {
        printf("getaddrinfo: %s\n", gai_strerror(error));
        exit(EXIT_FAILURE);
    }
}

static char *store_str_into_the_heap(char *str)
{
    char *result = malloc(sizeof(char) * strlen(str) +1 );

    strcpy(result, str);

    return result;
}

static int *store_int_into_the_heap(int numb)
{
    int *result = malloc(sizeof(int));

    *result = numb;

    return result;
}

static char *extract_ip_from_addrinfo(struct addrinfo *address_infos)
{
    char ip_buff[50];

    int error = getnameinfo(address_infos->ai_addr, address_infos->ai_addrlen, ip_buff, sizeof(ip_buff),NULL,0,NI_NUMERICHOST);

    if (error != 0) 
    {
        printf("getaddrinfo: %s\n", gai_strerror(error));
        exit(EXIT_FAILURE);
    }
    
    char *ip = malloc(sizeof(char) * strlen(ip_buff) +1 );

    strcpy(ip, ip_buff);

    return ip;
}

static char *extract_canonname_from_addrinfo(struct addrinfo *address_infos)
{
    return store_str_into_the_heap(address_infos->ai_canonname);
}

static char *assign_domain_to_address(char *domain)
{
    return store_str_into_the_heap(domain);
}

static int *assign_ai_family_to_address(int ai_family)
{
    return store_int_into_the_heap(ai_family);
}

static int *assign_ai_socket_type_to_address(int ai_socket_type)
{
    return store_int_into_the_heap(ai_socket_type);
}

static int *assign_ai_protocol_to_address(int ai_protocol)
{
    return store_int_into_the_heap(ai_protocol);
}

struct Host_infos *extract_address_from_addrinfo(struct addrinfo *address_infos, char *domain)
{
    struct Host_infos *address = malloc(sizeof(struct Host_infos));

    address->family = assign_ai_family_to_address(address_infos->ai_family);
    address->protocol = assign_ai_protocol_to_address(address_infos->ai_protocol);
    address->socket_type = assign_ai_socket_type_to_address(address_infos->ai_socktype);
    address->ip = extract_ip_from_addrinfo(address_infos);
    address->canonname = extract_canonname_from_addrinfo(address_infos);
    address->domain = assign_domain_to_address(domain);

    printf("Ip address selected: %s\n",address->ip);

    return address;
}

struct Host_infos *try_to_select_and_extract_an_address(struct addrinfo *i, char *domain,int *sock_fd_result)
{
    struct Host_infos *result = NULL;

    int sock_fd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);

    if ( sock_fd == -1 ) return NULL;

    if ( connect(sock_fd, i->ai_addr, i->ai_addrlen) == 0 )
    {
        printf("DNS CALL: successfully connect to the server...\n");

        *sock_fd_result = sock_fd;

        result = extract_address_from_addrinfo(i,domain);
    }
    else { perror("error while trying to connect with the server"); }

    return result;
}

struct Host_infos *try_to_select_and_extract_an_ipv6_address(struct addrinfo *i, char *domain, int *sock_fd)
{
    if(i->ai_family != AF_INET6) return NULL;

    struct Host_infos *result = try_to_select_and_extract_an_address(i, domain, sock_fd);

    return result;
}

struct Host_infos *try_to_connect_to_server_with_one_of_the_address_infos_received(char *domain, struct addrinfo *response_dns, int *sock_fd)
{
    struct Host_infos *result = NULL;

    struct addrinfo *i = response_dns;

    int try_ipv6 = TRY_IPV6;

    while (1)
    {
        /* retry from the beginning */
        if(i == NULL && try_ipv6 == 1) { try_ipv6 = 0; i = response_dns; } 

        if(i == NULL && try_ipv6 == 0) break;
        
        if ( try_ipv6 ) result = try_to_select_and_extract_an_ipv6_address(i, domain, sock_fd);

        else result = try_to_select_and_extract_an_address(i, domain, sock_fd);

        if(result != NULL) break;

        i = i->ai_next;
    }

    return result;
}

struct Host_infos *dns_call(char *domain, int *sock_fd)
{
    struct addrinfo *response_dns = NULL;

    call_dns_to_get_address_infos(domain, &response_dns);

    struct Host_infos *address = try_to_connect_to_server_with_one_of_the_address_infos_received(domain, response_dns, sock_fd);

    freeaddrinfo(response_dns);

    return address;
}

int make_a_call_dns__and__cache_host_infos(char *domain_name, struct Host_infos *infos, int *sock_fd)
{
    infos = dns_call(domain_name,sock_fd);

    if(infos == NULL) { print_error_message("Got no result from the dns call...", domain_name); return 1; }

    serialize(HOSTS_INFOS_INDEX, HOSTS_INFOS_STORAGE, domain_name, HOST_INFOS_STRUCT_FORMAT, infos);

    write_into_table(domain_name, HOSTS_INFOS_TABLE);

    return 0;
}

static int create_socket__and__return_his_file_descriptor(int communication_family, int communication_semantics, int protocol)
{
    int sock_fd = socket(communication_family, communication_semantics, protocol);

    if(sock_fd < 0)
    {
        perror("error : during socket creation ");
        exit(1);
    } 

    return sock_fd;
}

static struct sockaddr_in create_internet_adresse(char *ip_server, int address_family, int port_server)
{
    struct sockaddr_in server_addresse;

    server_addresse.sin_family = address_family;

    server_addresse.sin_addr.s_addr = inet_addr(ip_server);
    
    server_addresse.sin_port = htons(port_server);

    return server_addresse;
}

void print_connection_success_message(struct Host_infos *infos)
{
    printf("\nConnection successfully established with the server...\n\n");
    printf("domain: %s\n", infos->domain);
    printf("ip: %s\n", infos->ip);
    printf("family: %s\n\n", *infos->family == AF_INET ? "AF_INET" : "AF_INET6");
}

int make_the_connection__and__return_the_socket_file_descriptor(struct Host_infos *infos)
{
    int sock_fd = create_socket__and__return_his_file_descriptor(*infos->family, *infos->socket_type, *infos->protocol);

    struct sockaddr_in addess = create_internet_adresse(infos->ip, *infos->family, PORT);

    if ( connect(sock_fd, (struct sockaddr*)(&addess), sizeof(addess)) == 0 ) print_connection_success_message(infos);

    else { perror("error"); return -1; }

    return sock_fd;
}

void make_a_call_dns__and__update_cache_host_infos(char *domain_name, struct Host_infos *infos, int *sock_fd)
{
    infos = dns_call(domain_name,sock_fd);

    if(infos == NULL) { print_error_message("Got no result from the dns call...", domain_name); exit(1); }

    update(HOSTS_INFOS_INDEX, HOSTS_INFOS_STORAGE, domain_name, HOST_INFOS_STRUCT_FORMAT, infos);
}

void set_socket_timeout(int sock_fd)
{
    struct timeval timeout;      
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    
    if (setsockopt (sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0)
        printf("setsockopt failed\n");

    if (setsockopt (sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) < 0)
        printf("setsockopt failed\n");
}


int connect_to_the_server(char *domain)
{
    int sock_fd = -1;

    struct Host_infos *infos = search_for_host_informations(domain);

    if ( infos == NULL )
    {
        int result_call_dns = make_a_call_dns__and__cache_host_infos(domain, infos, &sock_fd);

        if ( result_call_dns == 1 ) { print_error_message("while making a call dns and caching it...",domain); exit(1); }

        return sock_fd;
    } 

    sock_fd = make_the_connection__and__return_the_socket_file_descriptor(infos);

    if(sock_fd == -1) 
    { 
        print_error_message(strerror(errno), domain); 
        make_a_call_dns__and__update_cache_host_infos(domain, infos, &sock_fd);
        /* refactor to keep track error */
    }

    free(infos);

    set_socket_timeout(sock_fd);

    return sock_fd;
}

void initialize_ssl()
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void shutdown_ssl(SSL *ssl)
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void destroy_ssl(SSL *ssl)
{
    shutdown_ssl(ssl);
    ERR_free_strings();
    EVP_cleanup();
}


static void create_ssl_context(const SSL_METHOD **method, SSL_CTX **ctx)
{
    *method = TLS_method();

    *ctx = SSL_CTX_new(*method);

    if(*ctx == NULL)
    {
        perror("failed to create an TLS object context ");
        exit(1);
    }

    SSL_CTX_set_mode(*ctx, SSL_MODE_AUTO_RETRY);
}

static void create_ssl_object(SSL_CTX *ctx, SSL **ssl)
{
    *ssl = SSL_new(ctx);

    if(*ssl == NULL)
    {
        perror("failed during the creation of the SSL object ");
        exit(1);
    }
}

static void connect_the_ssl_object_with_the_socket_file_descriptor(int sock_fd, SSL *ssl)
{
    int result = SSL_set_fd(ssl, sock_fd);

    if(result != 1)
    {
        perror("failed while binding SSL object and the socket file descriptor ");
        exit(1);
    }
}

static void initiate_tls_handshake_with_server(SSL *ssl)
{
    int result = SSL_connect(ssl);

    SSL_get_error(ssl,result);

    if(result == 1) printf("The TLS/SSL handshake is successfully completed, a TLS/SSL connection has been established....\n");

    else
    {
        perror("error : Enable to complete the TLS handshake...\n");
        exit(1);
    }
}

SSL *make_the_ssl_handshake(int sock_fd)
{
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    initialize_ssl();

    create_ssl_context(&method, &ctx);

    create_ssl_object(ctx, &ssl);

    connect_the_ssl_object_with_the_socket_file_descriptor(sock_fd, ssl);

    initiate_tls_handshake_with_server(ssl);

    return ssl;
}

static void send_a_request_via_ssl(SSL *ssl, char *request)
{
    int result = SSL_write(ssl, request, strlen(request) + 1);

    if(result > 0) printf("the request is successfully send...\n\n");
    else 
    {
        perror("error : failed while sending the request...\n");
        exit(1);
    }
}

static int read_response_from_ssl(SSL *ssl, FILE *stdin, int buff_size)
{
    int reading_with_success = 0;

    printf("reading response...\n");

    char recvline[buff_size]; 
    memset(recvline, '\0', buff_size);

    int err = 0;

    while (err == SSL_ERROR_NONE) // 0
    {
        int bytes = SSL_read(ssl, recvline, sizeof(recvline));

        int err = SSL_get_error(ssl,bytes);

        printf("%d\n",err);

        fprintf(stdin,"%s",recvline);
        printf("%s\n",recvline);
        memset(recvline, '\0', buff_size);

        if(err== SSL_ERROR_ZERO_RETURN) //6
        {
            reading_with_success = 1;
            printf("response receive....\n\n");
            break;
        }

        if(err != 0)
        {
            printf("error while reading response...\n");
            break;
        }
    }

    SSL_shutdown(ssl);

    return reading_with_success;
}

int send_request_and_read_response(SSL *ssl, char *request, int buff_size)
{
    FILE *stdin = fopen(STDIN_PATH,"w");

    if(stdin == NULL) { printf("Unable to open stdin file %s, initialisation failed...\n", STDIN_PATH); exit(1); }

    printf("\nrequest:\n\n%s",request);

    send_a_request_via_ssl(ssl,request);

    int result = read_response_from_ssl(ssl, stdin, buff_size);

    fclose(stdin);

    return result;
}