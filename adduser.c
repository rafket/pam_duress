#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <math.h>

#define byte unsigned char
#define SALT_SIZE 16
#define HASH_ROUNDS 1000

char SALT_CHARS[65];

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

void genSalt(char* salt, int maxchar)
{
    int i, tmp;
    for(i=0; i<SALT_SIZE; ++i)
    {
        RAND_bytes((unsigned char*)&tmp, 1);
        salt[i]=SALT_CHARS[tmp%maxchar];
    }
    salt[SALT_SIZE]='\0';
}

int main(int argc, char* argv[])
{
    if(geteuid() != 0)
    {
        printf("This must be run as root\n");
        return 0;
    }
    if(argc!=4)
    {
        printf("Usage: %s username password path\n", argv[0]);
        return 0;
    }

    sprintf(SALT_CHARS, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./");
    char pass_salt[SALT_SIZE+1], enc_salt[SALT_SIZE+1], concat[2*SHA256_DIGEST_LENGTH + strlen(argv[2]) + 1], userhsh[SHA_DIGEST_LENGTH*2 + 1], script_path[sizeof("usr/share/duress/scripts/")+2*SHA256_DIGEST_LENGTH+1], str_pass_hash[2*SHA256_DIGEST_LENGTH+1];
    static byte userhash[SHA256_DIGEST_LENGTH], pass_hash[SHA256_DIGEST_LENGTH];
    byte inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen, i;
    EVP_CIPHER_CTX ctx;
    byte key[32], iv[32];
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;

    sha256hash(argv[1], userhash);
    byte2string(userhash, userhsh);
    sprintf(concat, "%s%s", (const char*)userhsh, (const char*)argv[2]);
    genSalt(pass_salt, 64);
    genSalt(enc_salt, 16);

    pbkdf2hash(concat, pass_salt, pass_hash);
    byte2string(pass_hash, str_pass_hash);

    sprintf(script_path, "/usr/share/duress/scripts/%s", str_pass_hash);

    cipher = EVP_aes_256_cbc();
    dgst = EVP_sha256();
    FILE *in=fopen(argv[3], "rb"), *out=fopen(script_path, "wb");
    fprintf(out, "Salted__");

    byte tmpsalt[SALT_SIZE/2];
    for(i=0; i<SALT_SIZE/2; ++i)
    {
        if(enc_salt[2*i]>='a')
            tmpsalt[i]=(enc_salt[2*i]-'a'+10)*16;
        else
            tmpsalt[i]=(enc_salt[2*i]-'0')*16;
        if(enc_salt[2*i+1]>='a')
            tmpsalt[i]+=(enc_salt[2*i+1]-'a'+10);
        else
            tmpsalt[i]+=(enc_salt[2*i+1]-'0');
    }
    fwrite(tmpsalt, 8, 1, out);

    EVP_BytesToKey(cipher, dgst, (const byte *)tmpsalt, (byte *) argv[2], strlen(argv[2]), 1, key, iv);
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);

    while(inlen=fread(inbuf, 1, 1024, in), inlen > 0)
    {
        if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
        {
            fprintf(stderr, "Error in script encryption!\n");
            EVP_CIPHER_CTX_cleanup(&ctx);
            fclose(in);
            fclose(out);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if(!EVP_EncryptFinal_ex(&ctx, outbuf, &outlen))
    {
        fprintf(stderr, "Error in script decryption!\n");
        EVP_CIPHER_CTX_cleanup(&ctx);
        fclose(in);
        fclose(out);
        return 0;
    }

    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_cleanup(&ctx);
    fclose(in);
    fclose(out);

    FILE *hashes=fopen("/usr/share/duress/hashes", "a");
    fprintf(hashes, "%s:%s\n", pass_salt, str_pass_hash);
    fclose(hashes);

    return 0;
}
