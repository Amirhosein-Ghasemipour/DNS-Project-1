/* File-based adapter to jq's real UTF-8 validation module.
 * Contract: RFC 3629 UTF-8 -> valid/0; malformed UTF-8 -> invalid/2.
 * The exact-sized allocation makes a deliberately removed bounds check visible
 * to ASan. The adapter itself is identical in all four evaluation versions.
 */
#include "src/jv_unicode.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 3;
    FILE *input = fopen(argv[1], "rb");
    if (input == NULL) return 3;
    unsigned char buffer[4096];
    size_t length = fread(buffer, 1, sizeof(buffer), input);
    int failed = ferror(input);
    fclose(input);
    if (failed || length == sizeof(buffer)) return 3;
    char *text = malloc(length ? length : 1);
    if (text == NULL) return 3;
    for (size_t i = 0; i < length; i++) text[i] = (char)buffer[i];
    int valid = jvp_utf8_is_valid(text, text + length);
    free(text);
    puts(valid ? "valid" : "invalid");
    return valid ? 0 : 2;
}
