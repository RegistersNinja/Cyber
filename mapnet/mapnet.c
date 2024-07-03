/*
Plan:
   Usage:
    mapnet help or mapnet
    mapnet [host]  <scans for 1024 ports>
    mapnet [host] [port range] <scans for port range>

    help: When portScanner is invoked with this option, it should display the various options 
    available to the user.
    
    ports: You portScanner will scan all ports [1-1024] by default. 
    However, if this option is specified, it will scan ports specified on the command line.
    
    ip/file: These options allow a user to scan an individual IP address or a list of IP addresses 
    from a file respectively. When IP addresses are specified in a file, you can assume them to be one on each line. A user may invoke the portScanner with more than one of these options. If none of these options are specified, check for the presence of an individual IP address as an argument. If that check also fails, flag an error and ask the user to try again.
    
    Sources:
    Project outline - https://legacy.cs.indiana.edu/classes/p438/projects/portScan.html
    Socket programming - https://beej.us/guide/bgnet/html/index-wide.html
    
    
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>

void help()
{
    printf("Usage: mapnet [flags]\n");
    printf("Examples:\nmapnet help\nmapnet [host IPv4 Address] to scan 1024 most common ports\nmapnet [host IPv4 Address] [port start] [port end] to scan ports\n");
    printf("\nFlags:\n");
    printf("  help          Display this help message\n");
    printf("  [host]        IPv4 address of the host to scan\n");
    printf("  [port range]  Range of ports to scan (e.g., 1-1024)\n");
}

int scan_host(char host[], char ports[])
{
    int status, socketfd, conn;
//It feels wasteful to have ports in both formats, but I didn't have a better idea    
    char ch_port[10];
    char *token = strtok(ports, "-");
    int port_s = atoi(token);
    int port_e = port_s;

    token = strtok(NULL, "-");
    if (token != NULL) {
        port_e = atoi(token);
    }
//You can easily add here tcp/udp input from user, or expand to IPv6
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    for (int port = port_s; port <= port_e; port++)
    {
        snprintf(ch_port, sizeof ch_port, "%d", port);
        status = getaddrinfo(host, ch_port, &hints, &res);
        if (status != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
            continue;
        }
        socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (socketfd == -1) 
        {
            perror("socket");
            freeaddrinfo(res);
            continue; 
        }
        
        conn = connect(socketfd, res->ai_addr, res->ai_addrlen);
        printf("Port %d is ", port);
       
        if (conn != -1)
            printf("open\n");
        else
            printf("closed\n");

//Don't forget to free memory to avoid overflow
        close(socketfd);
        freeaddrinfo(res);
    }

    return 0;
}

int main(int argc, char *argv[])
{
   
    if (argc < 2 || argc > 4) {
        printf("Syntax is wrong\n");
        help();
        return 1;
    }

    if (strcmp(argv[1], "help") == 0)
    {
        help();
        return 0;
    }
    
    char default_ports[] = "1-1024";
//In the future handle arguments with argp
    switch (argc)
    {
        case 2:
            scan_host(argv[1], default_ports);
            break;
        case 3:
            scan_host(argv[1], argv[2]);
            break;
        default:
            printf("Syntax is wrong\n");
            help();
            break;
    }

    return 0;
}