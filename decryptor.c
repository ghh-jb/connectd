#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define KEY_HEX "4a8d2b30afc617d6f91843ded1f0d014" // launchd md5 hash from macos ventura 
// sysctl kern.version: Darwin Kernel Version 22.6.0: Mon Feb 19 19:48:53 PST 2024; root:xnu-8796.141.3.704.6~1/RELEASE_X86_64
// MacBook air 2018
#define KEY_BYTES 16

static int hex2bin(const char *hex, unsigned char *bin, size_t bin_len) {
    size_t len = strlen(hex);
    if (len != bin_len * 2) return -1;
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%02x", &byte) != 1) return -1;
        bin[i] = (unsigned char)byte;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <in.bin> <out>\n", argv[0]);
        return 1;
    }

    FILE *in = fopen(argv[1], "rb");
    if (!in) { perror("fopen input"); return 1; }

    unsigned char iv[16];
    if (fread(iv, 1, 16, in) != 16) {
        fprintf(stderr, "Failed to read IV (file too short)\n");
        fclose(in);
        return 1;
    }

    unsigned char key[KEY_BYTES];
    if (hex2bin(KEY_HEX, key, KEY_BYTES) != 0) {
        fprintf(stderr, "Invalid key hex\n");
        fclose(in);
        return 1;
    }

    FILE *out = fopen(argv[2], "wb");
    if (!out) { perror("fopen output"); fclose(in); return 1; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { perror("EVP_CIPHER_CTX_new"); fclose(in); fclose(out); return 1; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "DecryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in); fclose(out);
        return 1;
    }

    unsigned char inbuf[4096], outbuf[4096 + EVP_CIPHER_CTX_block_size(ctx)];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "DecryptUpdate failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in); fclose(out);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "DecryptFinal failed (wrong key? corrupted?)\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in); fclose(out);
        return 1;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    printf("Decryption successful: %s\n", argv[2]);
    return 0;
}
