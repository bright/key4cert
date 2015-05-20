/*
 * Copyright (C) 2015 Michal Lukasiewicz <michal.lukasiewicz@gmail.com>.
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * This project incorporates parts of Keychain Access project by Torsten Becker
 * (https://github.com/torsten/keychain_access) and code samples from
 * Zakir Durumeric's post "Parsing X.509 Certificates with OpenSSL and C"
 * (https://zakird.com/2013/10/13/certificate-parsing-with-openssl)
 *
 * NSData_Conversion category adpoted from http://stackoverflow.com/a/9084784/59666
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <Foundation/Foundation.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>

@interface NSData (NSData_Conversion)

#pragma mark - String Conversion

- (NSString *)hexadecimalString;

@end

@implementation NSData (NSData_Conversion)

#pragma mark - String Conversion

- (NSString *)hexadecimalString {
    /* Returns hexadecimal string of NSData. Empty string if data is empty.   */

    const unsigned char *dataBuffer = (const unsigned char *) [self bytes];

    if (!dataBuffer) {
        return [NSString string];
    }

    NSUInteger dataLength = [self length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];

    for (int i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long) dataBuffer[i]]];
    }

    return [NSString stringWithString:hexString];
}

@end


NSString *readSubjectKeyIdentifierFromItem(SecKeychainItemRef itemRef) {
    UInt32 tag = kSecKeyLabel;
    SecKeychainAttributeInfo info;
    info.count = 1;
    info.tag = &tag;
    info.format = NULL;
    SecItemClass itemClass;
    SecKeychainAttributeList *attrList = NULL;
    UInt32 length = 0;
    void *outdata = NULL;

    SecKeychainItemCopyAttributesAndData(itemRef, &info, &itemClass, &attrList, &length, &outdata);

    if (attrList != NULL) {
        for (int i = 0; i < attrList->count; i++) {
            SecKeychainAttribute attr = attrList->attr[i];
            char buffer[1024];
            if (attr.length < sizeof(buffer)) {
                strncpy (buffer, attr.data, attr.length);
                buffer[attr.length] = '\0';

                NSData *value = [NSData dataWithBytes:attrList->attr[0].data length:attrList->attr[0].length];
                NSString *key = [value hexadecimalString].uppercaseString;

                return key;

            }
        }
    }

    return nil;

}

BOOL privateKeyMatchesSecurityKeyIdentifier(SecKeychainItemRef itemRef, NSString *securityKeyIdentifierToMatch) {
    NSString *subjectKeyIdentifierFromPrivateKey = readSubjectKeyIdentifierFromItem(itemRef);
    return [subjectKeyIdentifierFromPrivateKey caseInsensitiveCompare:securityKeyIdentifierToMatch] == NSOrderedSame;
}

int printPrivateKey(SecKeychainItemRef p_keyItem) {

    CFDataRef exportKey;

    exportKey = CFDataCreate(NULL, (unsigned char *) "12345", 5);

    SecKeyImportExportParameters keyParams;
    keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    keyParams.flags = 0; // kSecKeySecurePassphrase
    keyParams.passphrase = exportKey;
    keyParams.alertTitle = 0;
    keyParams.alertPrompt = 0;

    CFDataRef exportedData;
    OSStatus status;

    status = SecKeychainItemExport(
            p_keyItem,
            kSecFormatWrappedPKCS8,
            kSecItemPemArmour,
            &keyParams,
            &exportedData);

    if (status == noErr) {

        int opensslPipe[2];
        if (pipe(opensslPipe) != 0) {
            perror("pipe(2) error");
            return 1;
        }

        FILE *fp;
        fp = fdopen(opensslPipe[0], "r");
        if (fp == NULL) {
            perror("fdopen(3) error");
            return 1;
        }

        ssize_t written;
        written = write(opensslPipe[1],
                CFDataGetBytePtr(exportedData), CFDataGetLength(exportedData));

        if (written < CFDataGetLength(exportedData)) {
            perror("write(2) error");
            return 1;
        }

        // Close pipe, so OpenSSL sees an end
        close(opensslPipe[1]);

        // Init OpenSSL
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();

        // Read key through this pipe
        X509_SIG *p8;
        p8 = PEM_read_PKCS8(fp, NULL, NULL, NULL);

        // Try to decrypt
        PKCS8_PRIV_KEY_INFO *p8inf;
        p8inf = PKCS8_decrypt(p8, "12345", 5);

        X509_SIG_free(p8);


        EVP_PKEY *pkey;

        if (!(pkey = EVP_PKCS82PKEY(p8inf))) {
            fprintf(stderr, "Error converting key\n");
            ERR_print_errors_fp(stderr);
            return 1;
        }

        PKCS8_PRIV_KEY_INFO_free(p8inf);

        PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    }
    else {
        fprintf(stderr, "Export error: %ld\n", status);
        return 1;
    }

    return 0;
}


SecKeychainItemRef findPrivateKeyWithSubjectKeyIdentifier(NSString *subjectKeyIdentifier) {
    OSStatus status = 0;
    SecKeychainSearchRef searchRef = 0;
    SecKeychainItemRef itemRef = 0;
    SecItemClass itemClass;

    status = SecKeychainSearchCreateFromAttributes(
            NULL,
            CSSM_DL_DB_RECORD_ANY,
            NULL,
            &searchRef);

    if (status != noErr) {
        fprintf(stderr, "Could not find any private key");
        return NULL;
    }

    status = SecKeychainSearchCopyNext(searchRef, &itemRef);
    while (status == noErr) {

        status = SecKeychainItemCopyContent(itemRef, &itemClass, NULL, NULL, NULL);

        if (status == noErr
                && itemClass == CSSM_DL_DB_RECORD_PRIVATE_KEY
                && privateKeyMatchesSecurityKeyIdentifier(itemRef, subjectKeyIdentifier)) {
            return itemRef;
        }

        status = SecKeychainSearchCopyNext(searchRef, &itemRef);
    }

    return NULL;
}


void printHelp(FILE *p_fp, const char *p_arg0) {
    fprintf(p_fp,
            "Usage: %s [-vh] <certificate_path>\n"
                    "Options:\n"
                    "  -h                    Show this information.\n"
                    "  -v                    Print current version number.\n"
                    "  <certificate_path>  The path to the certificate file that matches the private key that you want to export.",
            p_arg0);
}

NSString *readSubjectKeyIdentifierFromPath(const char *p_certPath) {

    FILE *fp;
    fp = fopen(p_certPath, "r");
    X509 *cert = d2i_X509_fp(fp, NULL);

    STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;

    int num_of_exts = 0;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
    }

    for (int i = 0; i < num_of_exts; i++) {

        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        int nid = OBJ_obj2nid(obj);
        if (nid != 82) {  // 82 == X509v3 Subject Key Identifier
            continue;
        }
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
            exit(0);
        }

        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        BIO_free(ext_bio);

//        printf("X509v3 Subject Key Identifier is %s\n", bptr->data);

        char *data = bptr->data;
        NSString *subjectKeyIdentifierFormatted = [NSString stringWithUTF8String:data];
        NSString *subjectKeyIdentifierRaw = [subjectKeyIdentifierFormatted stringByReplacingOccurrencesOfString:@":" withString:@""];
        return subjectKeyIdentifierRaw;
    }

    return nil;

}

int extractPrivateKey(char *p_certPath) {

    NSString *subjectKeyIdentifier = readSubjectKeyIdentifierFromPath(p_certPath);

    SecKeychainItemRef privateKey = findPrivateKeyWithSubjectKeyIdentifier(subjectKeyIdentifier);
    if (privateKey) {
        printPrivateKey(privateKey);
    }

    return 0;

}

void printVersion() {
#ifndef K4C_VERSION
#define K4C_VERSION "v0"
#endif
#ifndef K4C_REV
#define K4C_REV "n/a"
#endif

    printf("key4Cert "K4C_VERSION" ("K4C_REV")\n");
}

int main(int p_argc, char **p_argv) {
    int option;

    const char *arg0 = "key4cert";
    if (p_argc >= 1) {
        arg0 = p_argv[0];
    }

    while ((option = getopt(p_argc, p_argv, "vh")) != -1) {
        switch (option) {
            case 'h':
                printHelp(stdout, arg0);
                return 0;

            case 'v':
                printVersion();
                return 0;

            case '?':
            default:
                printHelp(stderr, arg0);
                return 1;
        }
    }

    int argcAfter = p_argc - optind;
    char *keyName = *(p_argv + optind);

    if (argcAfter > 1) {
        fprintf(stderr, "%s: Too many arguments.\n", arg0);
        printHelp(stderr, arg0);
        return 1;
    }
    else if (argcAfter < 1) {
        fprintf(stderr, "%s: Missing certificate path.\n", arg0);
        printHelp(stderr, arg0);
        return 1;
    }
    return extractPrivateKey(keyName);
}
