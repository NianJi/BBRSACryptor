//
//  main.m
//  rsatool
//
//  Created by 念纪 on 16/6/8.
//  Copyright © 2016年 liukun. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "BBRSACryptor.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        
        
        BOOL test = 1;
        if (0) {
            NSString *privateKey = @"/Users/Luke/AliDrive/tmall/tmatmosphere/3.0/private.key";
            NSString *publicKey = @"/Users/Luke/AliDrive/tmall/tmatmosphere/3.0/public.key";
            NSString *file = @"/Users/Luke/AliDrive/tmall/tmatmosphere/3.0/daliy_rainbowbar_ios.zip";
            NSString *signFile = @"/Users/Luke/AliDrive/tmall/tmatmosphere/3.0/signfile";
            
            // 验证
            BBRSACryptor *cryptor = [[BBRSACryptor alloc] init];
            [cryptor importRSAPrivateKeyPEMData:[NSData dataWithContentsOfFile:privateKey]];
            [cryptor importRSAPublicKeyPEMData:[NSData dataWithContentsOfFile:publicKey]];
            
            NSDictionary *digestTypeDic = @{@"md5": @(RSA_SIGN_DIGEST_TYPE_MD5),
                                            @"sha1": @(RSA_SIGN_DIGEST_TYPE_SHA1),
                                            @"sha256": @(RSA_SIGN_DIGEST_TYPE_SHA256),
                                            @"sha384": @(RSA_SIGN_DIGEST_TYPE_SHA384),
                                            @"sha512": @(RSA_SIGN_DIGEST_TYPE_SHA512),
                                            @"sha224": @(RSA_SIGN_DIGEST_TYPE_SHA224),
                                            };
            
            for (NSString *digestType in digestTypeDic.allKeys) {
                
                {
                    NSData *sign = [cryptor signWithPrivateKeyUsingDigest:[digestTypeDic[digestType] intValue]
                                                                plainData:[NSData dataWithContentsOfFile:file]];
                    
                    NSLog(@"sign: %@", sign);
                    [sign writeToFile:signFile atomically:YES];
                }
                
                {
                    BOOL ret = [cryptor verifyWithPublicKeyUsingDigest:[digestTypeDic[digestType] intValue]
                                                              signData:[NSData dataWithContentsOfFile:signFile]
                                                             plainData:[NSData dataWithContentsOfFile:file]];
                    
                    NSLog(@"verify: %@", ret ? @"YES" : @"NO");
                }
            }
            
            
        }
        
        if (argc <= 1) {
            return 0;
        }
        
        NSString *command = [NSString stringWithUTF8String:argv[1]];
        
        // read byte array of file
        if ([command isEqualToString:@"read"]) {
            
            NSString *filePath = [NSString stringWithUTF8String:argv[2]];
            NSData *data = [NSData dataWithContentsOfFile:filePath];
            
            NSMutableString *byteStr = [[NSMutableString alloc] initWithString:@"{"];
            
            const char *bytes = [data bytes];
            for (int i = 0; i < data.length; i++) {
                [byteStr appendFormat:@"%d,", bytes[i]];
            }
            
            [byteStr deleteCharactersInRange:NSMakeRange(byteStr.length-1, 1)];
            [byteStr appendString:@"}"];
            NSLog(@"byte array is: %@", byteStr);
        }
        else if ([command isEqualToString:@"sign"]) {
            
            NSString *digestType = [NSString stringWithUTF8String:argv[2]];
            NSString *keyPath = [NSString stringWithUTF8String:argv[3]];
            NSString *filePath = [NSString stringWithUTF8String:argv[4]];

            NSDictionary *digestTypeDic = @{@"md5": @(RSA_SIGN_DIGEST_TYPE_MD5),
                                            @"sha1": @(RSA_SIGN_DIGEST_TYPE_SHA1),
                                            @"sha256": @(RSA_SIGN_DIGEST_TYPE_SHA256),
                                            @"sha384": @(RSA_SIGN_DIGEST_TYPE_SHA384),
                                            @"sha512": @(RSA_SIGN_DIGEST_TYPE_SHA512),
                                            @"sha224": @(RSA_SIGN_DIGEST_TYPE_SHA224),
                                            };
            
            BBRSACryptor *cryptor = [[BBRSACryptor alloc] init];
            NSData *keyData = [NSData dataWithContentsOfFile:keyPath];
            [cryptor importRSAPrivateKeyPEMData:keyData];
            
            NSData *sign = [cryptor signWithPrivateKeyUsingDigest:[digestTypeDic[digestType] intValue]
                                                        plainData:[NSData dataWithContentsOfFile:filePath]];
            
            NSLog(@"%@", sign);
            [sign writeToFile:@"signfile" atomically:YES];
        }
        else if ([command isEqualToString:@"verify"]) {
            
            NSString *digestType = [NSString stringWithUTF8String:argv[2]];
            NSString *keyPath = [NSString stringWithUTF8String:argv[3]];
            NSString *filePath = [NSString stringWithUTF8String:argv[4]];
            NSString *signFile = [NSString stringWithUTF8String:argv[5]];
            
            NSDictionary *digestTypeDic = @{@"md5": @(RSA_SIGN_DIGEST_TYPE_MD5),
                                            @"sha1": @(RSA_SIGN_DIGEST_TYPE_SHA1),
                                            @"sha256": @(RSA_SIGN_DIGEST_TYPE_SHA256),
                                            @"sha384": @(RSA_SIGN_DIGEST_TYPE_SHA384),
                                            @"sha512": @(RSA_SIGN_DIGEST_TYPE_SHA512),
                                            @"sha224": @(RSA_SIGN_DIGEST_TYPE_SHA224),
                                            };
            
            BBRSACryptor *cryptor = [[BBRSACryptor alloc] init];
            NSData *keyData = [NSData dataWithContentsOfFile:keyPath];
            [cryptor importRSAPublicKeyPEMData:keyData];
            
            BOOL ret = [cryptor verifyWithPublicKeyUsingDigest:[digestTypeDic[digestType] intValue]
                                                      signData:[NSData dataWithContentsOfFile:signFile]
                                                     plainData:[NSData dataWithContentsOfFile:filePath]];
            
            NSLog(@"%@", ret ? @"YES" : @"NO");
        }
    }
    return 0;
}
