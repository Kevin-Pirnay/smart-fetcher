#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fetch.h"
#include "../parser/parser.h"

#define REQUEST_TEMPLATE "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json, text/plain, */*\r\nAccept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: no-cache\r\n\r\n"

char *construct_init_request(char *init_url, char *domain)
{
    char *request = malloc(strlen(REQUEST_TEMPLATE) + strlen(init_url) + strlen(domain) + 1);

    sprintf(request, REQUEST_TEMPLATE, init_url, domain);

    return request;
}

int send_initial_request(char *domain, char *init_url, int buff_size)
{
    init_stderr();

    char *request = construct_init_request(init_url, domain);

    int sock_fd = connect_to_the_server(domain);

    SSL *ssl = make_the_ssl_handshake(sock_fd);

    int is_success = send_request_and_read_response(ssl, request, buff_size);

    free(request);
    destroy_ssl(ssl);

    return is_success;
}

char *find_link(FILE *stdin)
{
    fseek(stdin, 0, SEEK_SET);

    char c;

    while (1)
    {
        c = fgetc(stdin);

        if(c == EOF) break;

        
    }
}

int find_and_store_link(FILE *stdin)
{
    
}

int main(int argc, char const *argv[])
{
    char *domain = "www.rtbf.be";
    char *init_url = "/";

    int result = send_initial_request(domain, init_url, 100000); //put sdin as an argv

    if ( result == 0 ) { printf("error occured on the request...\n"); exit(1); }



    return 0;
}

