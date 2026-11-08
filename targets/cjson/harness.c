/* Local API driver for the public cJSON_SetValuestring NULL-field case.
 * '=' updates an ordinary string; '!' constructs the corrupted string object
 * used by the upstream regression test. Other inputs are rejected.
 */
#include "cJSON.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    char input[4097];
    size_t n = fread(input, 1, sizeof(input) - 1, stdin);
    if (ferror(stdin) || n == 0 || n == sizeof(input) - 1 || memchr(input, '\0', n)) {
        puts("invalid");
        return 2;
    }
    input[n] = '\0';
    if (input[0] == '!') {
        cJSON corrupted = {0};
        corrupted.type = cJSON_String;
        if (cJSON_SetValuestring(&corrupted, input + 1) == NULL) {
            puts("invalid");
            return 2;
        }
        return 3;
    }
    if (input[0] != '=') {
        puts("invalid");
        return 2;
    }
    cJSON *value = cJSON_CreateString("seed");
    if (value == NULL) return 3;
    if (cJSON_SetValuestring(value, input + 1) == NULL) {
        cJSON_Delete(value);
        puts("invalid");
        return 2;
    }
    puts(value->valuestring);
    cJSON_Delete(value);
    return 0;
}

