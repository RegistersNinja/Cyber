/**
 * webserver.c -- A webserver written in C
 * 
 * Test with curl (if you don't have it, install it):
 * 
 *    curl -D - http://localhost:3490/
 *    curl -D - http://localhost:3490/d20
 *    curl -D - http://localhost:3490/date
 * 
 * You can also test the above URLs in your browser! They should work!
 * 
 * Posting Data:
 * 
 *    curl -D - -X POST -H 'Content-Type: text/plain' -d 'Hello, sample data!' http://localhost:3490/save
 * 
 * (Posting data is harder to test from a browser.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/file.h>
#include <fcntl.h>
#include "net.h"
#include "file.h"
#include "mime.h"
#include "cache.h"



#define PORT "3490"  // the port users will be connecting to

#define SERVER_FILES "./serverfiles"
#define SERVER_ROOT "./serverroot"

/**
 * Send an HTTP response
 *
 * header:       "HTTP/1.1 404 NOT FOUND" or "HTTP/1.1 200 OK", etc.
 * content_type: "text/plain", etc.
 * body:         the data to send.
 * 
 * Return the value from the send() function.
 */
int send_response(int fd, char *header, char *content_type, void *body, int content_length)
{
    const int max_response_size = 262144;
    char response[max_response_size];
    printf("Sending response\n");
    ///////////////////
    
    char* date_str = (char*)malloc(64); 
    time_t t = time(NULL);
    struct tm *lt = localtime(&t);
    strftime(date_str, 64, "%a, %d %b %Y %H:%M:%S", lt);
    
    int header_length = sprintf(response,
    "%s\r\n"
    "Date: %s\r\n"
    "Connection: close\r\n"
    "Content-Length: %d\r\n"
    "Content-Type: %s\r\n\r\n",
    header,
    date_str,
    content_length,
    content_type);

    int response_length = header_length+content_length;
    if (response_length >= max_response_size) {
        fprintf(stderr, "Response exceeds maximum size\n");
        return -1;
    }
    memcpy(response+header_length,body,content_length);
    int rv = send(fd, response, response_length, 0);
    if (rv < 0) {
        perror("send");
        return -1;
    }
    return rv;   

    ///////////////////
}


/**
 * Send a /d20 endpoint response
 */
void get_d20(int fd)
{
    printf("In get_d20\n");
    ///////////////////
    // Generate a random number between 1 and 20 inclusive
    srand(time(NULL));   
    int r = (rand()%20)+1;
    //
    // Use send_response() to send it back as text/plain data
    char header[] = "HTTP/1.1 200 OK";
    char content_type[] = "text/html";
    char content[60];
    int content_length = sprintf(content,"<!DOCTYPE html><html><body><h1>%d</h1></body></html>",r);
    int rv;
    rv=send_response(fd, &header, &content_type, &content, content_length);
    if ((rv) < 0) 
    {
        perror("get_d20");
    }
    
    ///////////////////
}

/**
 * Send a 404 response
 */
void resp_404(int fd)
{
    char filepath[4096];
    struct file_data *filedata; 
    char *mime_type;

    // Fetch the 404.html file
    snprintf(filepath, sizeof filepath, "%s/404.html", SERVER_FILES);
    filedata = file_load(filepath);

    if (filedata == NULL) {
        // TODO: make this non-fatal
        fprintf(stderr, "cannot find system 404 file\n");
        exit(3);
    }

    mime_type = mime_type_get(filepath);

    send_response(fd, "HTTP/1.1 404 NOT FOUND", mime_type, filedata->data, filedata->size);

    file_free(filedata);
}

/**
 * Read and return a file from disk or cache
 */
void get_file(int fd, struct cache *cache, char *request_path)
{
    ///////////////////

    printf("In get_file\n");
    struct file_data* requested_file;
    requested_file = file_load(request_path);
    char *content_type = mime_type_get(request_path);
    printf("files size is: %d\n",requested_file->size);
    printf("files content is: %s\n",requested_file->data);
    int sr = send_response(fd, "HTTP/1.1 200 OK", content_type,requested_file->data, requested_file->size);

    ///////////////////
}

/**
 * Search for the end of the HTTP header
 * 
 * "Newlines" in HTTP can be \r\n (carriage return followed by newline) or \n
 * (newline) or \r (carriage return).
 */
char *find_start_of_body(char *header)
{
    ///////////////////
    // IMPLEMENT ME! // (Stretch)
    ///////////////////
}

/**
 * Handle HTTP request and send response
 */
void handle_http_request(int fd, struct cache *cache)
{
    const int request_buffer_size = 65536; // 64K
    char request[request_buffer_size];

    // Read request
    int bytes_recvd = recv(fd, request, request_buffer_size - 1, 0);

    if (bytes_recvd < 0) {
        perror("recv");
        return;
    }
    ///////////////////
    char method[10],path[50];
    sscanf(request,"%s %s",method, path);
    printf("The method: %s\nThe path: %s\n",method,path);
    void* is_in_cache = cache_get(cache,path);
    if(is_in_cache != NULL)
        {
            printf("Serving file from cache: %s\n",path);
            get_file(fd,cache,path);

            return;
        }
    if(strcmp(&method, "GET")==0)
    {
        if(strcmp(&path, "/d20")==0)
        {
            printf("Returning random number between 1 and 20\n");
            get_d20(fd);
        }
        else 
        {
            char root_path[] = "./serverroot";
            strcat(root_path,path);
            printf("Serving file: %s\n",root_path);
            get_file(fd,cache,root_path);
        }
    }
    else resp_404(fd);
    
    ///////////////////

    // Read the first two components of the first line of the request 
 
    // If GET, handle the get endpoints

    //    Check if it's /d20 and handle that special case
    //    Otherwise serve the requested file by calling get_file()


    // (Stretch) If POST, handle the post request

}

/**
 * Main
 */
int main(void)
{
    int newfd;  // listen on sock_fd, new connection on newfd
    struct sockaddr_storage their_addr; // connector's address information
    char s[INET6_ADDRSTRLEN];

    struct cache *cache = cache_create(10, 0);

    // Get a listening socket
    int listenfd = get_listener_socket(PORT);

    if (listenfd < 0) {
        fprintf(stderr, "webserver: fatal error getting listening socket\n");
        exit(1);
    }

    printf("webserver: waiting for connections on port %s...\n", PORT);

    // This is the main loop that accepts incoming connections and
    // responds to the request. The main parent process
    // then goes back to waiting for new connections.
    
    while(1) {
        socklen_t sin_size = sizeof their_addr;

        // Parent process will block on the accept() call until someone
        // makes a new connection:
        newfd = accept(listenfd, (struct sockaddr *)&their_addr, &sin_size);
        if (newfd == -1) {
            perror("accept");
            continue;
        }
        // Print out a message that we got the connection
        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);
        // newfd is a new socket descriptor for the new connection.
        // listenfd is still listening for new connections.
        handle_http_request(newfd, cache);
        
        close(newfd);
    }

    // Unreachable code

    return 0;
}

