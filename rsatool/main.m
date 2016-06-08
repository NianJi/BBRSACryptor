//
//  main.m
//  rsatool
//
//  Created by 念纪 on 16/6/8.
//  Copyright © 2016年 liukun. All rights reserved.
//

#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
                
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
    }
    return 0;
}
