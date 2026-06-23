/*
main()
  ↓
fgets() 讀入使用者輸入
  ↓
trim_newline()
  ↓
process_input()
  ↓
validate_input()
  ↓
encode_for_log()
  ↓
dispatch()
  ↓
handle_request()
  ↓
write_record() *
  ↓
strcpy() 發生 buffer overflow
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct { 
  char encoded[128]; 
} Request;

typedef void (*Handler)(Request* req);

void trim_newline(char *s) {
  s[strcspn(s, "\n")] = '\0';
}

int validate_input(const char *input) {
    if (strlen(input) > 24) {
        printf("[validate] input too long\n");
        return 0;
    }

    return 1;
}

void encode_for_log(const char *src, char *dst, size_t dst_size) {
  size_t j = 0;
  for (size_t i =0; src[i] != '\0'; i++) {
    unsigned char c = (unsigned char)src[i];

    if (isalum(c)) {
      if (j + 1 < dst_size) {
        dst[j++] = c;
      }
    } else {
      if (j + 3 < dst_size) {
        snprintf(dst + j, dst_size - j, "%%%02X", c);
        j += 3;
        }
    }

  }
  dst[j] = '\0';
}

void write_record(Request *req) {
  char local_buf[32]; // Vulnerability: local_buf 只有 32 bytes，但 req->encoded 可能遠超過 32 bytes
  strcpy(local_buf, req->encoded);
  printf("[write_record] %s\n", local_buf);
}

void handle_request(Request *req) {
    printf("[handle_request] processing request\n");

    write_record(req);
}


void dispatch(Request *req, Handler handler) {
    handler(req);
}

void process_input(const char *user_input) {
    Request req;

    if (!validate_input(user_input)) {
        return;
    }

    encode_for_log(user_input, req.encoded, sizeof(req.encoded));

    dispatch(&req, handle_request);
}

int main() {
  /*
  1. 宣告 input[64]
  2. 用 fgets() 讀入使用者輸入
  3. 把 input 傳給 process_input()
  */
  char input[64];
  fgets(input, sizeof(input), stdin); //用 fgets() 讀入使用者輸入
  trim_newline(input);
  process_input(input);
  return 0;
}
