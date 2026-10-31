// Offline libsepol decision query. Never accesses selinuxfs or loads kernel policy.
#include <sepol/policydb/services.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 6) return 2;
    FILE *input=fopen(argv[1],"rb"); if (!input) return 3;
    if (fseek(input,0,SEEK_END)) return 4;
    long length=ftell(input); if(length<=0 || fseek(input,0,SEEK_SET)) return 4;
    void *data=malloc((size_t)length);if(!data)return 5;
    if(fread(data,1,(size_t)length,input)!=(size_t)length)return 6;
    fclose(input);
    int rc=sepol_load_policy(data,(size_t)length);free(data);
    if(rc){fprintf(stderr,"offline policy parse failed: %d\n",rc);return 7;}
    sepol_security_id_t source,target;sepol_security_class_t class;sepol_access_vector_t requested;
    if(sepol_context_to_sid(argv[2],strlen(argv[2])+1,&source) ||
       sepol_context_to_sid(argv[3],strlen(argv[3])+1,&target) ||
       sepol_string_to_security_class(argv[4],&class) ||
       sepol_string_to_av_perm(class,argv[5],&requested)) return 8;
    struct sepol_av_decision avd;unsigned int reason=0;
    rc=sepol_compute_av_reason(source,target,class,requested,&avd,&reason);
    if(rc)return 9;
    printf("{\"allowed\":%s,\"requested\":%u,\"allowed_mask\":%u,\"auditdeny_mask\":%u,\"reason_bits\":%u,\"scope\":\"offline saved reconstructed policy, not live KernelSU policy\"}\n",
           (avd.allowed&requested)==requested?"true":"false",requested,avd.allowed,avd.auditdeny,reason);
    return 0;
}