//
//  BBRSACryptor.m
//  BBRSACryptor-ios
//
//  Created by liukun on 14-3-21.
//  Copyright (c) 2014年 liukun. All rights reserved.
//

#import "BBRSACryptor.h"
#import <CommonCrypto/CommonCrypto.h>


#define DocumentsDir [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject]
#define OpenSSLRSAKeyDir [DocumentsDir stringByAppendingPathComponent:@".openssl_rsa"]
#define OpenSSLRSAPublicKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb.publicKey.pem"]
#define OpenSSLRSAPrivateKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb.privateKey.pem"]

#define BBRSAAssert(condition) NSAssert((condition), @"Invalid: %@", @#condition)

@implementation BBRSACryptor

- (void)dealloc
{
    if (_rsa) {
        RSA_free(_rsa);
    }
    if (_rsaPublic) {
        RSA_free(_rsaPublic);
    }
    if (_rsaPrivate) {
        RSA_free(_rsaPrivate);
    }
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        
        // mkdir for key dir
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:OpenSSLRSAKeyDir])
        {
            [fm createDirectoryAtPath:OpenSSLRSAKeyDir withIntermediateDirectories:YES attributes:nil error:nil];
        }
    }
    return self;
}

- (void)setPublicKey:(RSA *)publicKey
{
    if (_rsaPublic) {
        RSA_free(_rsaPublic);
    }
    _rsaPublic = publicKey;
}

- (void)setPrivateKey:(RSA *)privateKey
{
    if (_rsaPrivate) {
        RSA_free(_rsaPrivate);
    }
    _rsaPrivate = privateKey;
}

- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize
{
    if (NULL != _rsa)
    {
        RSA_free(_rsa);
        _rsa = NULL;
    }
    _rsa = RSA_generate_key(keySize,RSA_F4,NULL,NULL);
    BBRSAAssert(_rsa != NULL);
    
    const char *publicKeyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    const char *privateKeyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    
    //写入私钥和公钥
    RSA_blinding_on(_rsa, NULL);
    
    BIO *priBio = BIO_new_file(privateKeyFileName, "w");
    PEM_write_bio_RSAPrivateKey(priBio, _rsa, NULL, NULL, 0, NULL, NULL);
    
    BIO *pubBio = BIO_new_file(publicKeyFileName, "w");
    
    
    PEM_write_bio_RSA_PUBKEY(pubBio, _rsa);

    
    BIO_free(priBio);
    BIO_free(pubBio);
    
    //分别获取公钥和私钥
    [self setPrivateKey:RSAPrivateKey_dup(_rsa)];
    BBRSAAssert(_rsaPrivate != NULL);
    
    
    [self setPublicKey:RSAPublicKey_dup(_rsa)];
    BBRSAAssert(_rsaPublic != NULL);
    
    if (_rsa && _rsaPublic && _rsaPrivate)
    {
        return YES;
    }
    else
    {
        return NO;
    }
}

/**
 *  read public key from pem format data
 *  @param PEMData pem format key file data,
 *         like: -----BEGIN PUBLIC KEY-----   xxxxx  -----END PUBLIC KEY-----
 *  @return success or not.
 */
- (BOOL)importRSAPublicKeyPEMData:(NSData *)PEMData
{
    const void *bytes = [PEMData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)PEMData.length);
    
    [self setPublicKey:PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL)];

    BBRSAAssert(_rsaPublic != NULL);
    BIO_free_all(bio);
    
    return _rsaPublic ? YES : NO;
}

/**
 *  read public key from der format data
 *  @param DERData der format key file data.
 *  @return success or not.
 */
- (BOOL)importRSAPublicKeyDERData:(NSData *)DERData
{
    const void *bytes = [DERData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)DERData.length);
    
    [self setPublicKey:d2i_RSA_PUBKEY_bio(bio, NULL)];

    BBRSAAssert(_rsaPublic != NULL);
    BIO_free_all(bio);
    
    return _rsaPublic ? YES : NO;
}

/**
 *  read private key from pem format data
 *  @param PEMData pem format key file data,
 *         like: -----BEGIN RSA PRIVATE KEY-----   xxxxx  -----END RSA PRIVATE KEY-----
 *  @return success or not.
 */
- (BOOL)importRSAPrivateKeyPEMData:(NSData *)PEMData
{
    const void *bytes = [PEMData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)PEMData.length);
    [self setPrivateKey:PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL)];
    BBRSAAssert(_rsaPrivate != NULL);
    BIO_free_all(bio);
    
    return _rsaPrivate ? YES : NO;
}

/**
 *  read private key from der format data
 *  @param DERData der format key file data.
 *  @return success or not.
 */
- (BOOL)importRSAPrivateKeyDERData:(NSData *)DERData
{
    const void *bytes = [DERData bytes];
    
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)DERData.length);
    [self setPrivateKey:d2i_RSAPrivateKey_bio(bio, NULL)];
    BBRSAAssert(_rsaPrivate != NULL);
    BIO_free_all(bio);
    
    return _rsaPrivate ? YES : NO;
}

- (BOOL)importRSAPublicKeyBase64:(NSString *)publicKey
{
    //格式化公钥
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [publicKey length]; ++i) {
        
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END PUBLIC KEY-----"];
    [result writeToFile:OpenSSLRSAPublicKeyFile
             atomically:YES
               encoding:NSASCIIStringEncoding
                  error:NULL];
    
    FILE *publicKeyFile;
    const char *publicKeyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    publicKeyFile = fopen(publicKeyFileName,"rb");
    if (NULL != publicKeyFile)
    {
        BIO *bpubkey = NULL;
        bpubkey = BIO_new(BIO_s_file());
        BIO_read_filename(bpubkey, publicKeyFileName);
        
        [self setPublicKey:PEM_read_bio_RSA_PUBKEY(bpubkey, NULL, NULL, NULL)];
        BBRSAAssert(_rsaPublic != NULL);
        BIO_free_all(bpubkey);
        fclose(publicKeyFile);
    }
    
    return YES;
}

- (BOOL)importRSAPrivateKeyBase64:(NSString *)privateKey
{
    //格式化私钥
    const char *pstr = [privateKey UTF8String];
    int len = (int)[privateKey length];
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    int index = 0;
    int count = 0;
    while (index < len) {
        char ch = pstr[index];
        if (ch == '\r' || ch == '\n') {
            ++index;
            continue;
        }
        [result appendFormat:@"%c", ch];
        if (++count == 64)
        {
            [result appendString:@"\n"];
            count = 0;
        }
        index++;
    }
    [result appendString:@"\n-----END RSA PRIVATE KEY-----"];
    [result writeToFile:OpenSSLRSAPrivateKeyFile
             atomically:YES
               encoding:NSASCIIStringEncoding
                  error:NULL];
    
    FILE *privateKeyFile;
    const char *privateKeyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    privateKeyFile = fopen(privateKeyFileName,"rb");
    if (NULL != privateKeyFile)
    {
        BIO *bpubkey = NULL;
        bpubkey = BIO_new(BIO_s_file());
        BIO_read_filename(bpubkey, privateKeyFileName);
        
        [self setPrivateKey:PEM_read_bio_RSAPrivateKey(bpubkey, NULL, NULL, NULL)];
        BBRSAAssert(_rsaPrivate != NULL);
        BIO_free_all(bpubkey);
        fclose(privateKeyFile);
    }
    
    return YES;
}

/**
 *  get PEM format string of public key
 *  @return pem key file content
 */
- (NSString *)PEMFormatPublicKey
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    if (!_rsaPublic) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, _rsaPublic);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);

    return [NSString stringWithUTF8String:bptr->data];
}

/**
 *  get PEM format string of private key
 *  @return pem key file content
 */
- (NSString *)PEMFormatPrivateKey
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    if (!_rsaPrivate) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, _rsaPrivate, NULL, NULL, 0, NULL, NULL);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    
    return [NSString stringWithUTF8String:bptr->data];
}

- (NSString *)base64EncodedPublicKey
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:OpenSSLRSAPublicKeyFile])
    {
        NSString *str = [NSString stringWithContentsOfFile:OpenSSLRSAPublicKeyFile encoding:NSUTF8StringEncoding error:nil];
        NSString *string = [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
        string = [string stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        string = [string stringByReplacingOccurrencesOfString:@"\r" withString:@""];
        return string;
    }
    return nil;
}

- (NSString *)base64EncodedPrivateKey
{
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:OpenSSLRSAPrivateKeyFile])
    {
        NSString *str = [NSString stringWithContentsOfFile:OpenSSLRSAPrivateKeyFile encoding:NSUTF8StringEncoding error:nil];
        NSString *string = [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
        string = [string stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        string = [string stringByReplacingOccurrencesOfString:@"\r" withString:@""];
        return string;
    }
    return nil;
}

- (NSData *)encryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding plainData:(NSData *)plainData
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    
    if ([plainData length])
    {
        int len = (int)[plainData length];
        //result len
        int clen = RSA_size(_rsaPublic);
        int blocklen = clen - 11;
        int blockCount = (int)ceil((double)len/blocklen);
        
        NSMutableData *mutableData = [NSMutableData data];
        for (int i = 0; i < blockCount; i++) {
            int loc = i * blocklen;
            int reallen = MIN(blocklen, len - loc);
            NSData *segmentData = [plainData subdataWithRange:NSMakeRange(loc, reallen)];
            
            unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
            unsigned char *segmentBuffer = (unsigned char *)[segmentData bytes];
            RSA_public_encrypt(reallen, segmentBuffer, cipherBuffer, _rsaPublic,  padding);
            
            NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
            if (cipherData) {
                [mutableData appendData:cipherData];
            }
            
            free(cipherBuffer);
        }
        return [mutableData copy];
    }
    
    return nil;
}

- (NSData *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding plainData:(NSData *)plainData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    if ([plainData length])
    {
        int len = (int)[plainData length];
        //result len
        int clen = RSA_size(_rsaPrivate);
        int blocklen = clen - 11;
        int blockCount = (int)ceil((double)len/blocklen);
        
        NSMutableData *mutableData = [NSMutableData data];
        for (int i = 0; i < blockCount; i++) {
            int loc = i * blocklen;
            int reallen = MIN(blocklen, len - loc);
            NSData *segmentData = [plainData subdataWithRange:NSMakeRange(loc, reallen)];
            
            unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
            unsigned char *segmentBuffer = (unsigned char *)[segmentData bytes];
            RSA_public_encrypt(reallen, segmentBuffer, cipherBuffer, _rsaPrivate,  padding);
            
            NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
            if (cipherData) {
                [mutableData appendData:cipherData];
            }
            
            free(cipherBuffer);
        }
        return [mutableData copy];
    }
    
    return nil;
}

- (NSData *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    if ([cipherData length])
    {
        int len = (int)[cipherData length];
        //result len
        int mlen = RSA_size(_rsaPrivate);
        int blocklen = mlen;
        int blockCount = (int)ceil((double)len/blocklen);
        
        NSMutableData *mutableData = [NSMutableData data];
        for (int i = 0; i < blockCount; i++) {
            int loc = i * blocklen;
            int reallen = MIN(blocklen, len - loc);
            NSData *segmentData = [cipherData subdataWithRange:NSMakeRange(loc, reallen)];
            
            unsigned char *plainBuffer = calloc(mlen, sizeof(unsigned char));
            unsigned char *segmentBuffer = (unsigned char *)[segmentData bytes];
            RSA_private_decrypt(reallen, segmentBuffer, plainBuffer, _rsaPrivate, padding);
            
            NSData *plainData = [[NSData alloc] initWithBytes:plainBuffer length:strlen((char *)plainBuffer)];
            if (plainData) {
                [mutableData appendData:plainData];
            }
            
            free(plainBuffer);
        }
        return [mutableData copy];
    }
    
    return nil;
}

- (NSData *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    
    if ([cipherData length])
    {
        int len = (int)[cipherData length];
        //result len
        int mlen = RSA_size(_rsaPrivate);
        int blocklen = mlen;
        int blockCount = (int)ceil((double)len/blocklen);
        
        NSMutableData *mutableData = [NSMutableData data];
        for (int i = 0; i < blockCount; i++) {
            int loc = i * blocklen;
            int reallen = MIN(blocklen, len - loc);
            NSData *segmentData = [cipherData subdataWithRange:NSMakeRange(loc, reallen)];
            
            unsigned char *plainBuffer = calloc(mlen, sizeof(unsigned char));
            unsigned char *segmentBuffer = (unsigned char *)[segmentData bytes];
            RSA_public_decrypt(reallen, segmentBuffer, plainBuffer, _rsaPrivate, padding);
            
            NSData *plainData = [[NSData alloc] initWithBytes:plainBuffer length:strlen((char *)plainBuffer)];
            if (plainData) {
                [mutableData appendData:cipherData];
            }
            
            free(plainBuffer);
        }
        return [mutableData copy];
    }
    
    return nil;
}

- (NSData *)digestDataOfData:(NSData *)plainData withType:(RSA_SIGN_DIGEST_TYPE)type
{
    if (!plainData.length) {
        return nil;
    }
    
#define digestWithType(type) \
    unsigned char digest[CC_##type##_DIGEST_LENGTH];\
    CC_##type([plainData bytes], (unsigned int)[plainData length], digest);\
    NSData *result = [NSData dataWithBytes:digest length:CC_##type##_DIGEST_LENGTH];\
    return result;\

    switch (type) {
        case RSA_SIGN_DIGEST_TYPE_SHA1:
        {
            digestWithType(SHA1);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_SHA256:
        {
            digestWithType(SHA256);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_SHA224:
        {
            digestWithType(SHA224);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_SHA384:
        {
            digestWithType(SHA384);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_SHA512:
        {
            digestWithType(SHA512);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_MD5:
        {
            digestWithType(MD5);
        }
            break;
        default:
            break;
    }
    return nil;
}

- (NSData *)signWithPrivateKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type plainData:(NSData *)plainData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    NSData *digestData = [self digestDataOfData:plainData withType:type];
    
    unsigned int len = 0;
    unsigned int signLen = RSA_size(_rsaPrivate);
    unsigned char *sign = malloc(signLen);
    memset(sign, 0, signLen);
    
    int ret = RSA_sign(type, [digestData bytes], (unsigned int)[digestData length], sign, &len, _rsaPrivate);
    if (ret == 1) {
        NSData *data = [NSData dataWithBytes:sign length:len];
        free(sign);
        return data;
    }
    free(sign);
    return nil;
}

- (BOOL)verifyWithPublicKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type signData:(NSData *)signData plainData:(NSData *)plainData
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    NSData *digestData = [self digestDataOfData:plainData withType:type];
    
    int ret = RSA_verify(type, [digestData bytes], (unsigned int)[digestData length], [signData bytes], (unsigned int)[signData length], _rsaPublic);
    if (ret == 1) {
        return YES;
    }
    return NO;
}

@end
