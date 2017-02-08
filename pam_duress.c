#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <math.h>

#define byte unsigned char
#define INFINITE_LOOP_BOUND 1000000000
#define PATH_PREFIX "/usr/share/duress/actions/"
#define SALT_SIZE 16

static void
byte2string(const byte *in, char *out)
{
    int i;
    out[0] = '\0';
    for(i=0; i<SHA256_DIGEST_LENGTH; ++i)
        sprintf(out, "%s%02x", out, in[i]);
}

static void
sha256hash(const char* plaintext, byte* output)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext, strlen(plaintext));
    SHA256_Final(output, &sha256);
}

static void
pbkdf2hash(const char* pass, const char* salt, byte* output)
{
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), HASH_ROUNDS, EVP_sha256(), 32, output);
}

static void
decrypt(const char *input, const char *output, const char *pass, const byte *salt)
{
    FILE *in=fopen(input, "rb"), *out=fopen(output, "wb");
    fseek(in, sizeof(byte)*16, SEEK_SET);
    byte inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX ctx;
    byte key[32], iv[32];
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;

    cipher = EVP_aes_256_cbc();
    dgst = EVP_sha256();
    EVP_BytesToKey(cipher, dgst, (const byte *)salt, (byte *) pass, strlen(pass), 1, key, iv);

    EVP_CIPHER_CTX_init(&ctx);

    EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);

    while(inlen=fread(inbuf, 1, 1024, in), inlen > 0)
    {
        if(!EVP_DecryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
        {
            fprintf(stderr, "Error in action decryption!\n");
            EVP_CIPHER_CTX_cleanup(&ctx);
            fclose(in);
            fclose(out);
            return;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if(!EVP_DecryptFinal_ex(&ctx, outbuf, &outlen))
    {
        fprintf(stderr, "Error in action decryption!\n");
        EVP_CIPHER_CTX_cleanup(&ctx);
        fclose(in);
        fclose(out);
        return;
    }

    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_cleanup(&ctx);
    fclose(in);
    fclose(out);
}

static void
appendHashToPath(const byte* hexes, char* output)
{
    char hash[2*SHA256_DIGEST_LENGTH + 1];
    byte2string(hexes, hash);
    sprintf(output, "%s%s", output, hash);
}

static int
duressExistsInDatabase(char *concat, byte *hashin)
{
    int cntr = 0;
    char salt[SALT_SIZE+1], givenhash[SHA256_DIGEST_LENGTH*2 + 1], hashfromfile[SHA256_DIGEST_LENGTH*2 + 1];

    FILE*hashes=fopen("/usr/share/duress/hashes", "r");
    while(fscanf(hashes, "%16s:%64s\n", salt, hashfromfile) != EOF && cntr < INFINITE_LOOP_BOUND)
    {
        pbkdf2hash(concat, salt, hashin);
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

static void
readSalt(byte *salt, const char *path)
{
    FILE *in = fopen(path, "r");

    fseek(in, sizeof(byte)*8, SEEK_SET);
    fread(salt, 8, 1, in);

    fclose(in);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused, int argc, const char **argv)
{
    int retval, pam_retval;
    if(argc != 1)
    {
        fprintf(stderr, "Problem in pam_duress installation! Please add exactly one argument after the duress module!\n");
        return PAM_AUTH_ERR;
    }

    if(strcmp(argv[0], "disallow") == 0)
        pam_retval = PAM_AUTH_ERR;
    else if(strcmp(argv[0], "allow") == 0)
        pam_retval = PAM_SUCCESS;
    else
    {
        fprintf(stderr, "Unknown argument in pam_duress module!\n");
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
    sha256hash((char*)user, userhash);
    char userhsh[SHA256_DIGEST_LENGTH*2 + 1];

    byte2string(userhash, userhsh);

    char concat[2*SHA256_DIGEST_LENGTH + strlen(token) + 1];
    sprintf(concat, "%s%s", (const char*)userhsh, token);
    static byte hashin[SHA256_DIGEST_LENGTH];

    if(duressExistsInDatabase(concat, hashin)==1)
    {
        byte salt[8];
        char path[strlen(PATH_PREFIX) + 2*SHA256_DIGEST_LENGTH + 1];
        sprintf(path, PATH_PREFIX);
        appendHashToPath(hashin, path);
        readSalt(salt, path);
        decrypt(path, "/tmp/action", (char *)token, salt);
        chmod("/tmp/action", strtol("0544", 0, 8));
        pid_t pid=fork();
        if(pid==0)
        {
            execl("/tmp/action", "action", NULL, NULL);
            unlink("/tmp/action");
        }
        return pam_retval;
    }

    return PAM_AUTH_ERR;
}
