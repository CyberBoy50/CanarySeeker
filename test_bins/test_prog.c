#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void fill(char *dst, const char *src) {
    char buf[64];
    strcpy(buf, src);      /* fortifiable: becomes __strcpy_chk */
    memcpy(buf, src, 5);   /* fortifiable: becomes __memcpy_chk */
    printf("%s\n", buf);   /* fortifiable (literal format: stays plain) */
    strcpy(dst, buf);
}

int main(int argc, char **argv) {
    char name[32];
    if (argc > 1) {
        strcpy(name, argv[1]);
        fill(name, argv[1]);
    } else {
        fill(name, "hello");
    }
    printf("%s\n", name);
    return 0;
}
