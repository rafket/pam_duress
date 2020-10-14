#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <math.h>

#ifndef DB_PATH
#   define DB_PATH "/usr/share/duress"
#endif
#define PATH_PREFIX	DB_PATH "/actions/"
#define HASHES_PATH	DB_PATH "/hashes"
#define HASHES_PATH2	DB_PATH "/hashes.tmp"
#define byte unsigned char
#define SALT_SIZE 16

void byte2string(byte *in, char *out)
{
    int i;
    out[0] = '\0';
    for(i=0; i<SHA256_DIGEST_LENGTH; ++i)
        sprintf(out, "%s%02x", out, in[i]);
}

void sha256hash(char* plaintext, byte* output)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext, strlen(plaintext));
    SHA256_Final(output, &sha256);
}

void pbkdf2hash(char* pass, char* salt, byte* output)
{
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), HASH_ROUNDS, EVP_sha256(), 32, output);
}

void Usage(char *name)
{
    printf("Usage: %s username password\n", name);
}

int main(int argc, char* argv[])
{
    if(geteuid() != 0)
    {
        printf("This must be run as root\n");
        return 0;
    }

    char concat[2*SHA256_DIGEST_LENGTH + strlen(argv[2]) + 1], action_path[sizeof(PATH_PREFIX)+2*SHA256_DIGEST_LENGTH+1], *username, *password;
    static byte userhash[SHA256_DIGEST_LENGTH], hashin[SHA256_DIGEST_LENGTH];
    int i;
    char salt[SALT_SIZE+1], givenhash[SHA256_DIGEST_LENGTH*2 + 1], hashfromfile[SHA256_DIGEST_LENGTH*2 + 1];

    for(i=1; i<argc; ++i)
    {
        if(i==1)
            username=argv[1];
        else if(i==2)
            password=argv[2];
        else
        {
            Usage(argv[0]);
            return 0;
        }
    }

    if(i<2)
    {
        Usage(argv[0]);
        return 0;
    }

    FILE *hashes=fopen(HASHES_PATH, "r");
    FILE *hashes2=fopen(HASHES_PATH2, "w");

    if (hashes == NULL) {
        printf("%s: %m", HASHES_PATH);
        return 0;
    }

    sha256hash(username, userhash);
    byte2string(userhash, concat);
    strcpy(concat + 2*SHA256_DIGEST_LENGTH, password);
    i = 0;
    while(fscanf(hashes, "%16s:%64s\n", salt, hashfromfile) != EOF)
    {
        pbkdf2hash(concat, salt, hashin);
        byte2string(hashin, givenhash);

        if(strcmp(givenhash, hashfromfile) == 0)
        {
            sprintf(action_path, "%s%s", PATH_PREFIX, givenhash);
            unlink(action_path);
            fclose(hashes);
            i = 1;
        }
        else
        {
            fprintf(hashes2, "%s:%s\n", salt, hashfromfile);
        }
    }
    fclose(hashes);
    fclose(hashes2);

    if (i == 1)
    {
            unlink(HASHES_PATH);
            rename(HASHES_PATH2, HASHES_PATH);
            printf("Successfuly removed %s\n", username);
    }
    else
    {
        unlink(HASHES_PATH2);
        printf("User %s not found\n", username);
    }
    return 0;
}
