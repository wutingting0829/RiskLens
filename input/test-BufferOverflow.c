#include <stdio.h>
#include <string.h>
#include <stdlib.h>


void print_banner() {
    printf("==Multi-function Demo==\n");
}

void log_input(const char *input) {
    printf("[log] input length = %zu\n", strlen(input));
}
void unsafe_copy(const char *src) {
    char dest[8];
    strcpy(dest, src);
    printf("[copy] copied string: %s\n", dest);
}

void process_input(const char *user_input) {
    log_input(user_input);
    unsafe_copy(user_input);
}


int main(int argc, char *argv[]) {
    print_banner();
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    process_input(argv[1]);
    return 0;
}