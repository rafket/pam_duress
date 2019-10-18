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

#define byte unsigned char
#define SALT_SIZE 16

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

void Usage(char *name)
{
    printf("Usage: %s username password path [-r path] [-s salt]\n  Creates an entry for a user-password combination, encrypts the given script binary and copies it to the database\n  username: The username of the account\n  password: The password of the account\n  path: The path to the action to be executed (i.e. in the form of a script)\n  -r path (optional): After execution replace the encrypted action entry with an alternative (encrypted) entry located at path (works only for bash scripts)\n  -s salt (optional): Do not generate random salt but use the one given for password hashing (not recommended)\n", name);
}

void Encrypt(FILE *in, FILE *out, byte *pass, int passlen)
{
    EVP_CIPHER_CTX *ctx;
    byte key[32], iv[32], tmpsalt[SALT_SIZE/2], inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;
    char enc_salt[SALT_SIZE+1];
    int i, inlen, outlen;
    fprintf(out, "Salted__");

    cipher = EVP_aes_256_cbc();
    dgst = EVP_sha256();
    genSalt(enc_salt, 16);

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


    EVP_BytesToKey(cipher, dgst, (const byte*)tmpsalt, pass, passlen, 1, key, iv);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error in action encryption!\n");
        fclose(in);
        fclose(out);
        exit(0);
    }
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    while(inlen=fread(inbuf, 1, 1024, in), inlen > 0)
    {
        if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen))
        {
            fprintf(stderr, "Error in action encryption!\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            exit(0);
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if(!EVP_EncryptFinal_ex(ctx, outbuf, &outlen))
    {
        fprintf(stderr, "Error in action encryption!\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        exit(0);
    }

    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char* argv[])
{
    if(geteuid() != 0)
    {
        printf("This must be run as root\n");
        return 0;
    }

    char pass_salt[SALT_SIZE+1], concat[2*SHA256_DIGEST_LENGTH + strlen(argv[2]) + 1], userhsh[SHA_DIGEST_LENGTH*2 + 1], action_path[sizeof("usr/share/duress/actions/")+2*SHA256_DIGEST_LENGTH+1], str_pass_hash[2*SHA256_DIGEST_LENGTH+1], *username, *password, *path, *rPath;
    static byte userhash[SHA256_DIGEST_LENGTH], pass_hash[SHA256_DIGEST_LENGTH];
    int outlen, i, replace=0, gotsalt=0, cnt=0;

    for(i=1; i<argc; ++i)
    {
        if(argv[i][0]=='-' && argv[i][1]=='r')
        {
            replace=1;
            if(i==argc-1)
            {
                Usage(argv[0]);
                return 0;
            }
            rPath=argv[i+1];
            ++i;
        }
        else if(argv[i][0]=='-' && argv[i][1]=='s')
        {
            gotsalt=1;
            if(i==argc-1)
            {
                Usage(argv[0]);
                return 0;
            }
            if(strlen(argv[i+1])!=SALT_SIZE)
            {
                Usage(argv[0]);
                return 0;
            }
            strcpy(pass_salt, argv[i+1]);
        }
        else
        {
            if(cnt==0)
                username=argv[i];
            else if(cnt==1)
                password=argv[i];
            else if(cnt==2)
                path=argv[i];
            else
            {
                Usage(argv[0]);
                return 0;
            }
            ++cnt;
        }
    }

    if(cnt<3)
    {
        Usage(argv[0]);
        return 0;
    }

    sprintf(SALT_CHARS, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ./");

    sha256hash(username, userhash);
    byte2string(userhash, userhsh);
    sprintf(concat, "%s%s", (const char*)userhsh, (const char*)password);
    if(!gotsalt)
        genSalt(pass_salt, 64);

    pbkdf2hash(concat, pass_salt, pass_hash);
    byte2string(pass_hash, str_pass_hash);

    sprintf(action_path, "/usr/share/duress/actions/%s", str_pass_hash);

    if(replace)
    {
        FILE *in=fopen(path, "rb");
        FILE *out=fopen("/tmp/action", "wb");

        char buf[1024];
        size_t size;

        while(size=fread(buf, 1, 1024, in))
            fwrite(buf, 1, size, out);

        fprintf(out, "\nsudo sed '1,/<<REPLACE/d;1,/<<REPLACE/d;/REPLACE/,$d' /tmp/action | head -c -1 > %s\n", action_path);

        fclose(in);
        in=fopen(rPath, "rb");

        fprintf(out, "\n<<REPLACE\n");
        Encrypt(in, out, (byte *)password, strlen(password));
        fclose(in);
        fprintf(out, "\nREPLACE\n");
        fclose(out);

        in=fopen("/tmp/action", "rb");
        out=fopen(action_path, "wb");

        Encrypt(in, out, (byte *)password, strlen(password));

        fclose(in);
        fclose(out);

        unlink("/tmp/action");
    }
    else
    {
        FILE *in=fopen(path, "rb");
        FILE *out=fopen(action_path, "wb");
        Encrypt(in, out, (byte *)password, strlen(password));
        fclose(in);
        fclose(out);
    }

    chmod(action_path, strtol("0777", 0, 8));

    FILE *hashes=fopen("/usr/share/duress/hashes", "a");
    fprintf(hashes, "%s:%s\n", pass_salt, str_pass_hash);
    fclose(hashes);

    return 0;
}
