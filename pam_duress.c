#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <openssl/sha.h>
#include <math.h>

#define byte unsigned char
#define INFINITE_LOOP_BOUND 1000000000
#define PATH_PREFIX "/usr/share/duress/scripts/"
#define SALT_SIZE 16

void hashme(char* plaintext, byte* output)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext, strlen(plaintext));
    SHA256_Final(output, &sha256);
}

void byte2string(byte *in, char *out)
{
    int i;
    out[0] = '\0';
    for(i=0; i<SHA256_DIGEST_LENGTH; ++i)
        sprintf(out, "%s%02x", out, in[i]);
}

void appendHashToPath(byte* hexes, char* output)
{
    char hash[2*SHA256_DIGEST_LENGTH + 1];
    byte2string(hexes, hash);
    sprintf(output, "%s%s", output, hash);
}

int duressExistsInDatabase(char *concat, byte *hashin)
{
    byte X;
    int N, cntr=0, i, j;
    char salt[SALT_SIZE+1], salted[strlen(concat) + SALT_SIZE + 1], givenhash[SHA256_DIGEST_LENGTH*2 + 1], hashfromfile[SHA256_DIGEST_LENGTH*2 + 1];

    FILE*hashes=fopen("/usr/share/duress/hashes", "r");
    while(fscanf(hashes, "%16s:%64s\n", salt, hashfromfile) != EOF && cntr < INFINITE_LOOP_BOUND)
    {
        sprintf(salted, "%s%s", salt, concat);
        hashme(salted, hashin);
        byte2string(hashin, givenhash);

        if(strcmp(givenhash, hashfromfile) == 0)
        {
            fclose(hashes);
            return 1;
        }

        ++cntr;
    }
    fclose(hashes);
    return 0;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv )
{
    int retval, pam_retval;
    if(argc != 1)
    {
        printf("Problem in pam_duress installation! Please add exactly one argument after the duress module!\n");
        return PAM_AUTH_ERR;
    }

    if(strcmp(argv[0], "disallow") == 0)
        pam_retval = PAM_AUTH_ERR;
    else if(strcmp(argv[0], "allow") == 0)
        pam_retval = PAM_SUCCESS;
    else
    {
        printf("Unknown argument in pam_duress module!\n");
        return PAM_AUTH_ERR;
    }

    const char *token, *user;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &token, "Enter password: ");
    if(retval != PAM_SUCCESS)
        return retval;
    retval = pam_get_user(pamh, &user, "Enter username: ");
    if(retval != PAM_SUCCESS)
        return retval;

    static byte userhash[SHA256_DIGEST_LENGTH];
    hashme((char*)user, userhash);
    char userhsh[SHA256_DIGEST_LENGTH*2 + 1];

    byte2string(userhash, userhsh);

    char concat[2*SHA256_DIGEST_LENGTH + strlen(token) + 1];
    sprintf(concat, "%s%s", (const char*)userhsh, token);
    static byte hashin[SHA256_DIGEST_LENGTH];

    if(duressExistsInDatabase(concat, hashin)==1)
    {
        char path[strlen(PATH_PREFIX) + 2*SHA256_DIGEST_LENGTH + 1];
        sprintf(path, PATH_PREFIX);
        appendHashToPath(hashin, path);
        sprintf(path, "%s&", path);
        system(path);
        return pam_retval;
    }

    return PAM_AUTH_ERR;
}
