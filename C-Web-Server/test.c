#include <stdio.h>
#include <time.h>

int main(int argc, char const *argv[])
{
    // char header[50];
    // strcpy(header, "HTTP/1.1 404 NOT FOUND");
    // char date[50];
    // strcpy(date, "Date: Wed Dec 20 13:05:11 PST 2017");
    // char output[2000];

    // int bytes = sprintf(output, "%s\n\r%s", header, date);
    // printf("bytes: %d\noutput: %s", bytes, output);

    char header[] = "GET /example HTTP/1.1\n\r asdasfg dsfrhrty6  jdfgn etykj edfgn dtyk det ykidf yk";
    char method[4],path[sizeof header];
    sscanf(header,"%s %s",method,path);
    printf("%s\n%s",method,path);
    return 0;
}
