#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PAYLOAD 64
#define MAX_RECORD 32

typedef struct {
    char payload[MAX_PAYLOAD];
    size_t length;
} Message;

void function_A_write_record(const Message *msg) {
    char record[MAX_RECORD];
    printf("[A] received msg->len = %zu\n", msg->length);
    memcpy(record, msg->payload, msg->length); // Vulnerability: record 只有 MAX_RECORD bytes，但 msg->payload 可能遠超過 MAX_RECORD bytes
    record[MAX_RECORD - 1] = '\0';
    printf("[A] record = %s\n", record);
}

Message function_B_build_message(const char *user_input) {
    Message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.payload, sizeof(msg.payload), "%s", user_input);
    // Vulnerability: 如果 user_input 長度超過 MAX_PAYLOAD，會導致 msg.payload buffer overflow  
    
    msg.length = strlen(user_input);
    printf("[B] payload size = %zu\n", strlen(msg.payload));
    printf("[B] stored msg.length = %zu\n", msg.length);
    return msg;
}

void trim_newline(char *s) {
    s[strcspn(s, "\n")] = '\0';
}

int main() {
    char input[128];
    printf("Enter input:");
    fgets(input, sizeof(input), stdin);
    trim_newline(input);

    Message msg = function_B_build_message(input);
    function_A_write_record(&msg);
    return 0;
}

/*
Function B:
user_input → msg.payload
user_input length → msg.len

Function A:
msg.len → memcpy length
msg.payload → memcpy source
record[32] → memcpy destination

B 建立了一個不一致的資料結構：
payload 看起來被安全複製，
但 len 卻保留了未限制的原始輸入長度。
A 信任這個錯誤 len，因此在 memcpy 時 overflow。
*/