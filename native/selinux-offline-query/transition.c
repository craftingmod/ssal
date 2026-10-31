// Compute a creation context from a saved policy without loading it into a kernel.
#include <sepol/policydb/services.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    FILE *input = fopen(argv[1], "rb");
    if (!input || fseek(input, 0, SEEK_END)) return 3;
    long length = ftell(input);
    if (length <= 0 || fseek(input, 0, SEEK_SET)) return 3;
    void *data = malloc((size_t)length);
    if (!data || fread(data, 1, (size_t)length, input) != (size_t)length) return 4;
    fclose(input);
    int result = sepol_load_policy(data, (size_t)length);
    free(data);
    if (result) return 5;
    sepol_security_id_t source, target, created;
    sepol_security_class_t class;
    if (sepol_context_to_sid(argv[2], strlen(argv[2]) + 1, &source) ||
        sepol_context_to_sid(argv[3], strlen(argv[3]) + 1, &target) ||
        sepol_string_to_security_class(argv[4], &class) ||
        sepol_transition_sid(source, target, class, &created)) return 6;
    sepol_security_context_t context;
    size_t context_len;
    if (sepol_sid_to_context(created, &context, &context_len)) return 7;
    puts(context);
    free(context);
    return 0;
}
