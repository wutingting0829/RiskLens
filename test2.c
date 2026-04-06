#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void display_menu() {
    printf("=== User Management & Diagnostic System ===\n");
    printf("1. View Profile\n");
    printf("2. Update Bio\n");
    printf("3. Ping Server\n");
    printf("===========================================\n");
}


void print_user_profile(const char *username) {
    if (username != NULL) {
        printf("Loading profile for user: %s\n", username);
    } else {
        printf("Error: Invalid user.\n");
    }
}


void update_profile_bio(const char *user_input) {
    char local_bio[64];
    strcpy(local_bio, user_input);
    
    printf("Bio successfully updated to: %s\n", local_bio);
}

void check_server_status(const char *ip_address) {
    char command[256];
    sprintf(command, "ping -c 1 %s", ip_address);
    
    printf("Diagnostic tool running: %s\n", command);
    system(command);
}

int main() {
    display_menu();
    print_user_profile("Admin_01");

    printf("\n--- Test 1: Buffer Overflow Attack ---\n");
    const char *malicious_bio = "This_is_a_very_long_biography_string_that_will_definitely_exceed_sixty_four_bytes_limit_and_cause_stack_smashing!";

    printf("\n--- Test 2: Command Injection Attack ---\n");
    const char *malicious_ip = "8.8.8.8; echo 'YOU HAVE BEEN HACKED!'";
    check_server_status(malicious_ip);

    return 0;
}