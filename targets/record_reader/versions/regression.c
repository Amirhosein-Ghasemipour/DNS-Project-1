/* Deliberately defective LOCAL teaching fixture. Run only in the sandbox.
 * Contract: echo up to 16 bytes, reject longer records with "too long\n"/2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    unsigned char input[128];
    size_t length = fread(input, 1, sizeof(input), stdin);
    if (ferror(stdin)) return 3;
    if (length > 16) { puts("too long"); return 2; }
    if (length > 8) { puts("too long"); return 2; }
    unsigned char *record = malloc(16);
    if (record == NULL) return 3;
    memcpy(record, input, length);
    fwrite(record, 1, length, stdout);
    free(record);
    return 0;
}

