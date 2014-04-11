//
//  BBRSACryptor.h
//  BBRSACryptor-ios
//
//  Created by liukun on 14-3-21.
//  Copyright (c) 2014年 liukun. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>
#import <openssl/pem.h>

/**
 @abstract  padding type
 */
typedef NS_ENUM(NSInteger, RSA_PADDING_TYPE) {
    
    RSA_PADDING_TYPE_NONE       = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1      = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23     = RSA_SSLV23_PADDING
};

@interface BBRSACryptor : NSObject
{
    RSA *_rsaPublic;
    RSA *_rsaPrivate;
    
    @public
    RSA *_rsa;
}

/**
 Generate rsa key pair by the key size.
 @param keySize RSA key bits . The value could be `512`,`1024`,`2048` and so on.
 Normal is `1024`.
 */
- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize;

/**
 @abstract  import public key, call before 'encryptWithPublicKey'
 @param     publicKey with base64 encoded
 @return    Success or not.
 */
- (BOOL)importRSAPublicKeyBase64:(NSString *)publicKey;

/**
 @abstract  import private key, call before 'decryptWithPrivateKey'
 @param privateKey with base64 encoded
 @return Success or not.
 */
- (BOOL)importRSAPrivateKeyBase64:(NSString *)privateKey;

/**
 @abstract  export public key, 'generateRSAKeyPairWithKeySize' or 'importRSAPublicKeyBase64' should call before this method
 @return    public key base64 encoded
 */
- (NSString *)base64EncodedPublicKey;

/**
 @abstract  export public key, 'generateRSAKeyPairWithKeySize' or 'importRSAPrivateKeyBase64' should call before this method
 @return    private key base64 encoded
 */
- (NSString *)base64EncodedPrivateKey;

/**
 @abstract  encrypt text using RSA public key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)encryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding
                                   plainData:(NSData *)plainData;

/**
 @abstract  encrypt text using RSA private key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding
                                    plainData:(NSData *)plainData;

/**
 @abstract  decrypt text using RSA private key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding
                                   cipherData:(NSData *)cipherData;

/**
 @abstract  decrypt text using RSA public key
 @param     padding type add the plain text
 @return    encrypted data
 */
- (NSData *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding
                                  cipherData:(NSData *)cipherData;
@end
