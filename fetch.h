#ifndef FETCH_H
#define FETCH_H

#include <openssl/ssl.h>

int connect_to_the_server(char *domain);

SSL *make_the_ssl_handshake(int sock_fd);

int send_request_and_read_response(SSL *ssl, char *request, int buff_size);

void destroy_ssl(SSL *ssl);

void init_stderr();

#endif