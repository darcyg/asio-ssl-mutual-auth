#include <openssl/ssl.h>
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define LOGC(TEXT)      std::cout<<TEXT<<std::endl

int32_t main()
{
    SSL_CTX *ctx;
    SSL* ssl;
    SSL_METHOD *meth;

    int sd;
    struct sockaddr_in sa;
    char buffer[1024];

    LOGC("step 1");
    OpenSSL_add_ssl_algorithms();
    //meth = SSLv3_client_method();
    meth = (SSL_METHOD *)SSLv3_client_method();
    LOGC("step 2");

    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    LOGC("step 2.1");
    SSL_CTX_load_verify_locations(ctx,"certs/ca-cert.pem",NULL);
    LOGC("step 3");
    SSL_CTX_use_certificate_file(ctx,"certs/test-cert.pem",SSL_FILETYPE_PEM);
    //SSL_CTX_set_default_passwd_cb_userdata(ctx,"123456");
    SSL_CTX_use_PrivateKey_file(ctx,"certs/test-key.pem",SSL_FILETYPE_PEM);
    LOGC("step 4");
    if (!SSL_CTX_check_private_key(ctx)){
        std::cout<<"no check private key"<<std::endl;
        return 1;
    }

    sd = socket(AF_INET,SOCK_STREAM,0);
    memset(&sa,'\0',sizeof(sa));
    sa.sin_addr.s_addr = inet_addr("218.241.227.175");
    sa.sin_port = htons(8002);
    connect(sd,(struct sockaddr*)&sa,sizeof(sa));

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl,sd);
    if(SSL_connect(ssl)<=0){
        std::cout<<"no SSL connect"<<std::endl;
        return 1;
    }

    SSL_write(ssl,"test",4);
    SSL_read(ssl,buffer,sizeof(buffer)-1);
    shutdown(sd,0);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
