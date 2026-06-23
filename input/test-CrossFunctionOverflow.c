/*

main() 讀入資料
   ↓
handle_user_input()
   ↓
copy_to_stack_buffer()
   ↓
發生 buffer overflow

*/ 

#include <stdio.h>
#include <string.h>

void copy_to_stack_buffer(const char *input) {
    char bufferp[16];
    strcpy(bufferp, input);
    printf("Copied input: %s\n", bufferp);

}

void handle_user_input(const char *user_data) {
    printf("[handle_user_input] receiving user input...\n");

    copy_to_stack_buffer(user_data);
}

int main() {
    char input[128];
    printf("Enter your input: ");
    fgets(input, sizeof(input), stdin);
    handle_user_input(input);
    return 0;
}