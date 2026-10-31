// Enumerate raw rules that reference an attribute in a saved kernel policy.
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/util.h>
#include <stdio.h>
#include <stdlib.h>

static void scan(const policydb_t *policy, const avtab_t *table, unsigned int type,
                 const char *table_name) {
    for (unsigned int i = 0; i < table->nslot; i++) {
        for (avtab_ptr_t node = table->htable[i]; node; node = node->next) {
            const avtab_key_t *key = &node->key;
            if (key->source_type != type && key->target_type != type) continue;
            if (!key->source_type || key->source_type > policy->p_types.nprim ||
                !key->target_type || key->target_type > policy->p_types.nprim ||
                !key->target_class || key->target_class > policy->p_classes.nprim) exit(5);
            const char *source = policy->p_type_val_to_name[key->source_type - 1];
            const char *target = policy->p_type_val_to_name[key->target_type - 1];
            const char *class_name = policy->p_class_val_to_name[key->target_class - 1];
            if (!source || !target || !class_name) exit(5);
            char *permissions = NULL;
            if (key->specified & AVTAB_AV)
                permissions = sepol_av_to_string(policy, key->target_class, node->datum.data);
            printf("%s\t%s\t%s\t%s\t0x%04x\t0x%08x\t%s", table_name,
                   source, target, class_name, key->specified, node->datum.data,
                   permissions ? permissions : "-");
            if (key->specified & AVTAB_XPERMS) {
                if (!node->datum.xperms) exit(5);
                printf("\t0x%02x\t0x%02x", node->datum.xperms->specified,
                       node->datum.xperms->driver);
                for (unsigned int j = 0; j < 8; j++)
                    printf("\t%08x", node->datum.xperms->perms[j]);
            }
            putchar('\n');
            free(permissions);
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    FILE *file = fopen(argv[1], "rb");
    if (!file) return 3;
    policydb_t policy;
    policy_file_t input;
    policy_file_init(&input);
    input.type = PF_USE_STDIO;
    input.fp = file;
    if (policydb_init(&policy) || policydb_read(&policy, &input, 0)) return 4;
    type_datum_t *type = hashtab_search(policy.p_types.table, argv[2]);
    if (!type || type->flavor != TYPE_ATTRIB || !type->s.value) return 5;
    scan(&policy, &policy.te_avtab, type->s.value, "unconditional");
    scan(&policy, &policy.te_cond_avtab, type->s.value, "conditional");
    policydb_destroy(&policy);
    fclose(file);
    return 0;
}
