//
//  BBRSACryptorTests.m
//  BBRSACryptorTests
//
//  Created by longxdragon on 2017/4/27.
//  Copyright © 2017年 liukun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "BBRSACryptor.h"
#import <GTMBase64/GTMBase64.h>

@interface BBRSACryptorTests : XCTestCase
@property (nonatomic, strong) BBRSACryptor *rsaCryptor;
@end

@implementation BBRSACryptorTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    
    self.rsaCryptor = [[BBRSACryptor alloc] init];
    [self.rsaCryptor importRSAPublicKeyBase64:@"\
     MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMi5/u9mMlan1D6OyleUWdIG5PfldpDK\
     WnB8eC/d+BLh1e3PdtOfxrIMexZ5Njdmc/5B9KUT/X2L8sr9vOdbM4MCAwEAAQ=="];
    [self.rsaCryptor importRSAPrivateKeyBase64:@"\
     MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAyLn+72YyVqfUPo7K\
     V5RZ0gbk9+V2kMpacHx4L934EuHV7c9205/Gsgx7Fnk2N2Zz/kH0pRP9fYvyyv28\
     51szgwIDAQABAkEAoDSrP8HOfZFX+lIXN01lXxc3mo+fUTLgehUuC+5auB3ye+1A\
     sjr66CbDWxndwY4ymFrP1j5wRL/flb7TYvAa2QIhAPY/13ZRF0sdIov5SyD2umSC\
     zy/m3SivyFt4+yDRAS3fAiEA0Kyz0++ri0MTLMHCr48qTN9EoA+UIGX8sd0FxU1o\
     pt0CIQDR6F/JWpyJif9d5BaXtdnzPdJRGfGh8h3PY5RmR+NCbwIgJvXXrV42HQ4s\
     6lJS0wxbzXZyDaBa+6GPCHZHuYq2W1ECIA0ZWBAA53Iyruok+oxWjN9xROffwsFA\
     WyRE0r8b7QKp"];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPublicEncrypt {
    NSString *str = @"Test RSA encrypt!";
    
    NSData *rsaData = [self.rsaCryptor encryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainData:[str dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *result = [GTMBase64 stringByEncodingData:rsaData];
    
    XCTAssertNotNil(result, @"encrypt fail");
}

- (void)testPrivateDecrypt {
    NSString *str = @"wLgN4zcCEmwktSNlpXEBVC2IAI6xCTTgV9ttm/vfhdHQaom1hHnp4EwU/ZWiwsMH9VAr9HWZcPNikCvgjiwOhA==";
    
    NSData *base64Data = [GTMBase64 decodeString:str];
    NSData *rsaData = [self.rsaCryptor decryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:base64Data];
    NSString *result = [[NSString alloc] initWithData:rsaData encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(result, @"Test RSA encrypt!", @"encrypt fail");
}

- (void)testPrivetEncrypt {
    NSString *str = @"Test RSA encrypt!";
    
    NSData *rsaData = [self.rsaCryptor encryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainData:[str dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *result = [GTMBase64 stringByEncodingData:rsaData];
    
    XCTAssertNotNil(result, @"encrypt fail");
}

- (void)testPublicDecrypt {
    NSString *str = @"CsQr5KLt/IbAUz8P95rzLU6q11T7XI1lzeJmiMbjWE4/E1JS/lZcwrimgCaAXrdDR5jorLeZyLseyp4mvDe8bg==";
    
    NSData *base64Data = [GTMBase64 decodeString:str];
    NSData *rsaData = [self.rsaCryptor decryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:base64Data];
    NSString *result = [[NSString alloc] initWithData:rsaData encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(result, @"Test RSA encrypt!", @"encrypt fail");
}

- (void)testPublicSectionEncrypt {
    NSString *str = @"Test RSA encrypt! \
    的家都没拿绿卡是没电了凯撒的拉伸快没电了萨马德里马萨、、 &&&bd o=.de'dan c [dl;as,;\
    dmaskmdkasmdkc jadjknsjkdnandkasmdlkadksamdlkasmdkamkk////damskdmaksdakmsd\
    dansk cmkamndksamdapdmasldkjpoasmd;lamsdpoasnclas mcpxkasodmksamd;alsm";
    
    NSData *rsaData = [self.rsaCryptor encryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainData:[str dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *result = [GTMBase64 stringByEncodingData:rsaData];
    
    XCTAssertNotNil(result, @"encrypt fail");
}

- (void)testPrivateSectionDecrypt {
    NSString *str = @"N5Q6HjnaTnrKJH4xV1qBxXkeL2s2Az01dajeA9x+T0GJGtHAxNZaO6k/ccLf2mb7GngaEawOevw2vNXgxqXb4ZmXm+Ojqz89OeoNnRKpLen88dUOGJPnykzVPuxRHlw67v2YQMgTPMcMbF0xAsceB1OFtqS/I/chiF1ee2uLUrTB1PvJwaG4y+s0MdOYGI9LRK3Ce9CBZ2dflPpEgtkOp/r930PHCT/diETG03phP8tdMzptUrZoa5UgpmQ9EC42pAh0XX0/vx0bK1xn1OcT6WUAIp8l6Mo5anR8cAQrbSjydP0kZJP8Ta3N4OLK9P3mWbmK8ao/JvE98ov6EtY6noI0VrYEGKDKn9OoRVvmV29F2TjcRwNSYJEY7YMSMLWMgZHebHZ8L4KBZNwkr27m3NzQhEtcshvhthX+ljoSnOFzrMf+tj5VGXalMgift82Y8DHzZ6wGAuvbxtwJqdkpSKlt8rYbiNrXncvhedIkEdGQyDcCF18Q4otnjWOfq97B";
    NSString *str2 = @"Test RSA encrypt! \
    的家都没拿绿卡是没电了凯撒的拉伸快没电了萨马德里马萨、、 &&&bd o=.de'dan c [dl;as,;\
    dmaskmdkasmdkc jadjknsjkdnandkasmdlkadksamdlkasmdkamkk////damskdmaksdakmsd\
    dansk cmkamndksamdapdmasldkjpoasmd;lamsdpoasnclas mcpxkasodmksamd;alsm";
    
    NSData *base64Data = [GTMBase64 decodeString:str];
    NSData *rsaData = [self.rsaCryptor decryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:base64Data];
    NSString *result = [[NSString alloc] initWithData:rsaData encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(result, str2, @"encrypt fail");
}

- (void)testPrivetSectionEncrypt {
    NSString *str = @"Test RSA encrypt! \
    的家都没拿绿卡是没电了凯撒的拉伸快没电了萨马德里马萨、、 &&&bd o=.de'dan c [dl;as,;\
    dmaskmdkasmdkc jadjknsjkdnandkasmdlkadksamdlkasmdkamkk////damskdmaksdakmsd\
    dansk cmkamndksamdapdmasldkjpoasmd;lamsdpoasnclas mcpxkasodmksamd;alsm";
    
    NSData *rsaData = [self.rsaCryptor encryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainData:[str dataUsingEncoding:NSUTF8StringEncoding]];
    NSString *result = [GTMBase64 stringByEncodingData:rsaData];
    
    XCTAssertNotNil(result, @"encrypt fail");
}

- (void)testPublicSectionDecrypt {
    NSString *str = @"nPcHXzDwu8kLtaz9Wd3xc+1Fv+0nS2wJAq0Vi4YGiwyQ4PTwB5J3dJvvrJUblARRBDQzhOtxgYg+18+sXWhmTUdCUh2ENKItPKoixOIA0zQ8vFmICfq9/wLoHyR2Nj7z6dC5bbqM/YleHZeDq6fut4J8bWruLeacY+I4lWtnent89x8fL+RJ2dYwfwPbxOKnImuScABFPv5MPPA4IIvRym0gqhcahKioWywVQ94U0A7+YMoqswirineRYe8bIybDBM4oVr35ewtLX38M+D4iWeIzFtFSLBV0UHZwPmeD00CFqeSZhVMTxEjKc2laB504X+h+qKD35nzizl726+FslCiVo3Atv0uxkHiW7fbUrudrZCBUaBYJGj6YkpNo47OHIGtLxvSfPnHVxfDYpgbYL6K53d50MSfLwf7OpWWHrp54RnPd5BnT3cAbGdlDErL/CNLxOVXi1APyDEUfBDzfysABqNpaYPcBq29ThSVieooYG5wY0CyLNh2O4LkVpYqn";
    NSString *str2 = @"Test RSA encrypt! \
    的家都没拿绿卡是没电了凯撒的拉伸快没电了萨马德里马萨、、 &&&bd o=.de'dan c [dl;as,;\
    dmaskmdkasmdkc jadjknsjkdnandkasmdlkadksamdlkasmdkamkk////damskdmaksdakmsd\
    dansk cmkamndksamdapdmasldkjpoasmd;lamsdpoasnclas mcpxkasodmksamd;alsm";
    
    NSData *base64Data = [GTMBase64 decodeString:str];
    NSData *rsaData = [self.rsaCryptor decryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:base64Data];
    NSString *result = [[NSString alloc] initWithData:rsaData encoding:NSUTF8StringEncoding];
    
    XCTAssertEqualObjects(result, str2, @"encrypt fail");
}


- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
