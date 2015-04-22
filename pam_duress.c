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

int iseof;

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

void hashme(char* plaintext, byte* output)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext, strlen(plaintext));
    SHA256_Final(output, &sha256);
}

byte readHex()
{
    char c1, c2;
    if(scanf("%c%c", &c1, &c2) == EOF)
    {
        iseof = 1;
        return 0;
    }
    int X1, X2;
    if(c1 <= '9')
        X1 = c1-'0';
    else
        X1 = c1-'a'+10;
    if(c2 <= '9')
        X2 = c2-'0';
    else
        X2 = c2-'a'+10;
    return(byte)(X1*16+X2);
}

void appendHashToPath(byte* hexes, char* output)
{
    int i, X1, X2;
    char c1, c2;
    for(i=0; i<SHA256_DIGEST_LENGTH; ++i)
    {
        X1 = (((int)hexes[i])/16);
        X2 = ((int)hexes[i])%16;
        if(X1 <= 9)
            c1 = X1 + '0';
        else
            c1 = X1 + 'a' - 10;
        if(X2 <= 9)
            c2 = X2 + '0';
        else
            c2 = X2 + 'a' - 10;
        sprintf(output, "%s%c%c", output, c1, c2);
    }
}

int duressExistsInDatabase(char *concat, byte *hashin)
{
    int i, j;
    byte X;
    hashme(concat, hashin);
    int N, cntr=0;
    int flag=0, check;
    char nl;
    iseof = 0;
    freopen("/usr/share/duress/hashes", "r", stdin);
    while(iseof == 0 && cntr < INFINITE_LOOP_BOUND)
    {
        check = 1;
        for(j=0; j<SHA256_DIGEST_LENGTH; ++j)
        {
            X = readHex();
            if(iseof == 1)
            {
                check=0;
                break;
            }
            if(hashin[j] != X)
                check=0;
        }
        if(check != 0)
            flag = 1;
        ++cntr;
        scanf("%c", &nl);
    }
    fclose(stdin);
    if(flag == 1)
        return 1;
    return 0;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv )
{
    int retval;

    const char *token, *user;
    retval = pam_get_authtok(pamh, PAM_AUTHTOK, &token, "Password: ");
    if(retval != PAM_SUCCESS)
        return retval;
    retval = pam_get_user(pamh, &user, "Username: ");
    if(retval != PAM_SUCCESS)
        return retval;

    char concat[strlen(user) + strlen(token)];
    sprintf(concat, "%s%s", user, token);
    static byte hashin[SHA256_DIGEST_LENGTH];
    if(duressExistsInDatabase(concat, hashin)==1)
    {
        char path[strlen(PATH_PREFIX)+SHA256_DIGEST_LENGTH];
        sprintf(path, PATH_PREFIX);
        appendHashToPath(hashin, path);
        system(path);
        return PAM_SUCCESS;
    }

    return PAM_AUTH_ERR;
}
