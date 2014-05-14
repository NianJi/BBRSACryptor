//
//  BBRSACryptor.m
//  BBRSACryptor-ios
//
//  Created by liukun on 14-3-21.
//  Copyright (c) 2014年 liukun. All rights reserved.
//

#import "BBRSACryptor.h"

#define DocumentsDir [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject]
#define OpenSSLRSAKeyDir [DocumentsDir stringByAppendingPathComponent:@".openssl_rsa"]
#define OpenSSLRSAPublicKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb.publicKey.pem"]
#define OpenSSLRSAPrivateKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb.privateKey.pem"]

@implementation BBRSACryptor

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

- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize
{
    if (NULL != _rsa)
    {
        RSA_free(_rsa);
        _rsa = NULL;
    }
    _rsa = RSA_generate_key(keySize,RSA_F4,NULL,NULL);
    assert(_rsa != NULL);
    
    const char *publicKeyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    const char *privateKeyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];

    //写入私钥和公钥
    RSA_blinding_on(_rsa, NULL);
    
    BIO *priBio = BIO_new_file(privateKeyFileName, "w");
    PEM_write_bio_RSAPrivateKey(priBio, _rsa, NULL, NULL, 0, NULL, NULL);
    
    BIO *pubBio = BIO_new_file(publicKeyFileName, "w");
    PEM_write_bio_RSAPublicKey(pubBio, _rsa);
    
    BIO_free(priBio);
    BIO_free(pubBio);

    //分别获取公钥和私钥
    _rsaPrivate = RSAPrivateKey_dup(_rsa);
    assert(_rsaPrivate != NULL);
    
    _rsaPublic = RSAPublicKey_dup(_rsa);
    assert(_rsaPublic != NULL);
    
    if (_rsa && _rsaPublic && _rsaPrivate)
    {
        return YES;
    }
    else
    {
        return NO;
    }
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
        
        _rsaPublic = PEM_read_bio_RSA_PUBKEY(bpubkey, NULL, NULL, NULL);
        assert(_rsaPublic != NULL);
        BIO_free_all(bpubkey);
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
    return [result writeToFile:OpenSSLRSAPrivateKeyFile
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
        
        _rsaPrivate = PEM_read_bio_RSAPrivateKey(bpubkey, NULL, NULL, NULL);
        assert(_rsaPrivate != NULL);
        BIO_free_all(bpubkey);
    }
    
    return YES;
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
        unsigned char *plainBuffer = (unsigned char *)[plainData bytes];
        
        //result len
        int clen = RSA_size(_rsaPublic);
        unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
        
        RSA_public_encrypt(len,plainBuffer,cipherBuffer, _rsaPublic,  padding);
        
        NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
        
        free(cipherBuffer);
        
        return cipherData;
    }
    
    return nil;
}

- (NSData *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding plainData:(NSData *)plainData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    if ([plainData length])
    {
        int len = (int)[plainData length];
        unsigned char *plainBuffer = (unsigned char *)[plainData bytes];
        
        //result len
        int clen = RSA_size(_rsaPrivate);
        unsigned char *cipherBuffer = calloc(clen, sizeof(unsigned char));
        
        RSA_private_encrypt(len,plainBuffer,cipherBuffer, _rsaPrivate,  padding);
        
        NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
        
        free(cipherBuffer);
        
        return cipherData;
    }
    
    return nil;
}

- (NSData *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData
{
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    
    if ([cipherData length])
    {
        int len = (int)[cipherData length];
        unsigned char *cipherBuffer = (unsigned char *)[cipherData bytes];
        
        //result len
        int mlen = RSA_size(_rsaPrivate);
        unsigned char *plainBuffer = calloc(mlen, sizeof(unsigned char));
        
        RSA_private_decrypt(len, cipherBuffer, plainBuffer, _rsaPrivate, padding);
        
        NSData *plainData = [[NSData alloc] initWithBytes:plainBuffer length:mlen];
        
        free(plainBuffer);
        
        return plainData;
    }
    
    return nil;
}

- (NSData *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData
{
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    
    if ([cipherData length])
    {
        int len = (int)[cipherData length];
        unsigned char *cipherBuffer = (unsigned char *)[cipherData bytes];
        
        //result len
        int mlen = RSA_size(_rsaPublic);
        unsigned char *plainBuffer = calloc(mlen, sizeof(unsigned char));
        
        RSA_public_decrypt(len, cipherBuffer, plainBuffer, _rsaPublic, padding);
        
        NSData *plainData = [[NSData alloc] initWithBytes:plainBuffer length:mlen];
        
        free(plainBuffer);
        
        return plainData;
    }
    
    return nil;
}

@end
