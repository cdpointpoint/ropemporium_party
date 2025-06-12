#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int get_input(char *buf, int s) {
    char data[26];
    int n;
    n = read(0, data, s);
    return n;
}
int main(int argc, char **argv) {
    char buff[80];
    int i;
    i = get_input(buff, 80);
    printf("ret = %d\n",i);
    return(EXIT_SUCCESS);
}
