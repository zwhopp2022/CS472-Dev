#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include "http.h"

//---------------------------------------------------------------------------------
// TODO:  Documentation
//
// Note that this module includes a number of helper functions to support this
// assignment.  YOU DO NOT NEED TO MODIFY ANY OF THIS CODE.  What you need to do
// is to appropriately document the socket_connect(), get_http_header_len(), and
// get_http_content_len() functions.
//
// NOTE:  I am not looking for a line-by-line set of comments.  I am looking for
//        a comment block at the top of each function that clearly highlights you
//        understanding about how the function works and that you researched the
//        function calls that I used.  You may (and likely should) add additional
//        comments within the function body itself highlighting key aspects of
//        what is going on.
//
// There is also an optional extra credit activity at the end of this function. If
// you partake, you need to rewrite the body of this function with a more optimal
// implementation. See the directions for this if you want to take on the extra
// credit.
//--------------------------------------------------------------------------------

char *strcasestr(const char *s, const char *find)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != 0)
    {
        c = tolower((unsigned char)c);
        len = strlen(find);
        do
        {
            do
            {
                if ((sc = *s++) == 0)
                    return (NULL);
            } while ((char)tolower((unsigned char)sc) != c);
        } while (strncasecmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

char *strnstr(const char *s, const char *find, size_t slen)
{
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0')
    {
        len = strlen(find);
        do
        {
            do
            {
                if ((sc = *s++) == '\0' || slen-- < 1)
                    return (NULL);
            } while (sc != c);
            if (len > slen)
                return (NULL);
        } while (strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

// DOCUMENTATION
/*
Variables:
    hp: represents the details of a particular host
    addr: represents address and port information
    sock: socket file discriptor for connecting

Description:
    hp is initialized with information from DNS about the host. if it cant be resolved, -2 is returned. hp information is copied into addr's sin_address attribute
    if socket is created successfully, a connection is made to the host, if it is unsuccessful the socket is closed and error return value and print are executed. If successful, the socket file descriptor is returned.

*/
int socket_connect(const char *host, uint16_t port)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;

    if ((hp = gethostbyname(host)) == NULL)
    {
        herror("gethostbyname");
        return -2;
    }

    bcopy(hp->h_addr_list[0], &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock == -1)
    {
        perror("socket");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
    {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

// DOCUMENTATION
/*
Variables:
    end_ptr: represents the end position of the http header inside of the httpbuff
    header_len: represents the size (len) of the http header
Description:
    end_ptr is updated to the start of the end of the http header provided in http_buff using strnstr that finds the substring that matches the end of the HTTP header.
    If this function doesnt find the end of the header, it returns null and an error value of -1 is returned by get_http_header_len
    If it does find the end, the header len is calculated as the end_ptr - http_buff which returns the length of the header before the end and then the length of the end characters is added
    This value is then returned

*/
int get_http_header_len(char *http_buff, int http_buff_len)
{
    char *end_ptr;
    int header_len = 0;
    end_ptr = strnstr(http_buff, HTTP_HEADER_END, http_buff_len);

    if (end_ptr == NULL)
    {
        fprintf(stderr, "Could not find the end of the HTTP header\n");
        return -1;
    }

    header_len = (end_ptr - http_buff) + strlen(HTTP_HEADER_END);

    return header_len;
}

// DOCUMENTATION
/*
Variables:
    next_header_line: represents the next http content header
    end_header_buff: represents the start of the http content since it has the length of the http header added to the start of the http buffer
    header_line: buffer to represent current line of http header being examined
    isCLHeader: represents if the header line given is the Content-Length header line with no case requirement.
    isCLHeader2: represents the same as isCLHeader, calculated using strcasecmp instead
    header_value_start: represents the position of the next Header value(content length) based off the delimiter that separates the header values.
    header_value: represents the position of the first character of the next Header value
    content_len: represents the string to integer value of the content length.
Description:
    In this function, we go through each line of the header searching for the content length and extract its value and return it or 0 if the content length header value is not present.

*/
int get_http_content_len(char *http_buff, int http_header_len)
{
    char header_line[MAX_HEADER_LINE];

    char *next_header_line = http_buff;
    char *end_header_buff = http_buff + http_header_len;

    while (next_header_line < end_header_buff)
    {
        bzero(header_line, sizeof(header_line));
        sscanf(next_header_line, "%[^\r\n]s", header_line);

        char *isCLHeader2 = strcasecmp(header_line, CL_HEADER);
        char *isCLHeader = strcasestr(header_line, CL_HEADER);
        if (isCLHeader != NULL)
        {
            char *header_value_start = strchr(header_line, HTTP_HEADER_DELIM);
            if (header_value_start != NULL)
            {
                char *header_value = header_value_start + 1;
                int content_len = atoi(header_value);
                return content_len;
            }
        }
        next_header_line += strlen(header_line) + strlen(HTTP_HEADER_EOL);
    }
    fprintf(stderr, "Did not find content length\n");
    return 0;
}

// This function just prints the header, it might be helpful for your debugging
// You dont need to document this or do anything with it, its self explanitory. :-)
void print_header(char *http_buff, int http_header_len)
{
    fprintf(stdout, "%.*s\n", http_header_len, http_buff);
}

//--------------------------------------------------------------------------------------
// EXTRA CREDIT - 10 pts - READ BELOW
//
// Implement a function that processes the header in one pass to figure out BOTH the
// header length and the content length.  I provided an implementation below just to
// highlight what I DONT WANT, in that we are making 2 passes over the buffer to determine
// the header and content length.
//
// To get extra credit, you must process the buffer ONCE getting both the header and content
// length.  Note that you are also free to change the function signature, or use the one I have
// that is passing both of the values back via pointers.  If you change the interface dont forget
// to change the signature in the http.h header file :-).  You also need to update client-ka.c to
// use this function to get full extra credit.
//--------------------------------------------------------------------------------------
int process_http_header(char *http_buff, int http_buff_len, int *header_len, int *content_len)
{
    int h_len, c_len = 0;
    h_len = get_http_header_len(http_buff, http_buff_len);
    if (h_len < 0)
    {
        *header_len = 0;
        *content_len = 0;
        return -1;
    }
    c_len = get_http_content_len(http_buff, http_buff_len);
    if (c_len < 0)
    {
        *header_len = 0;
        *content_len = 0;
        return -1;
    }

    *header_len = h_len;
    *content_len = c_len;
    return 0; // success
}