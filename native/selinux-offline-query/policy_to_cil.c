// Convert a saved kernel policy using the linked libsepol; never loads it into a kernel.
#include <sepol/policydb/policydb.h>
#include <sepol/kernel_to_cil.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 3;
    policydb_t policy;
    policy_file_t input;
    policy_file_init(&input);
    input.type = PF_USE_STDIO;
    input.fp = file;
    if (policydb_init(&policy) || policydb_read(&policy, &input, 0)) return 4;
    int result = sepol_kernel_policydb_to_cil(stdout, &policy);
    if (fflush(stdout) != 0) result = -1;
    policydb_destroy(&policy);
    fclose(file);
    return result == 0 ? 0 : 5;
}
