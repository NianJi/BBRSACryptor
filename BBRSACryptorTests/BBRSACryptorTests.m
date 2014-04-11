//
//  BBRSACryptorTests.m
//  BBRSACryptorTests
//
//  Created by liukun on 14-2-28.
//  Copyright (c) 2014年 liukun. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "BBRSACryptor.h"

@interface BBRSACryptorTests : XCTestCase

@end

@implementation BBRSACryptorTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample
{
    NSString *publicKey =
    @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSh6+KnrtF37KHrGbWnfr9qlOs\r"
     "dtxER3CezagsRHbdBD9CLo3aCbRQMjG9f11Dyp0USB7eX0tc/naBvX4qXuKjeu8o\r"
     "PwnqyARRmUkiBHLwCRolSYJgzmSM6wpvd5R95uA/SfPTQgWulHV6b0c5AAT6Ei8k\r"
     "lHGtUHOXgXsnLihGWwIDAQAB\r";
    
    NSString *str = @"Test RSA encrypt!";
    
    NSString *result = [BBRSACryptor encryptString:str withPublicKey:publicKey];
    
    XCTAssertNotNil(result, @"encrypt fail");
}

@end
