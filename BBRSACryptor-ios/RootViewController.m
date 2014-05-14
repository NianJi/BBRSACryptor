//
//  RootViewController.m
//  BBRSACryptor-ios
//
//  Created by liukun on 14-3-21.
//  Copyright (c) 2014年 liukun. All rights reserved.
//

#import "RootViewController.h"
#import "BBRSACryptor.h"
#import "GTMBase64.h"

#define kRSAPublicKey  \
@"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSh6+KnrtF37KHrGbWnfr9qlOsdtxER3CezagsRHbdBD9CLo3aCbRQMjG9f11Dyp0USB7eX0tc/naBvX4qXuKjeu8oPwnqyARRmUkiBHLwCRolSYJgzmSM6wpvd5R95uA/SfPTQgWulHV6b0c5AAT6Ei8klHGtUHOXgXsnLihGWwIDAQAB"

@interface RootViewController () <UITextViewDelegate>

/** textfield */
@property (nonatomic, strong) UITextView *textView;
/** result text view */
@property (nonatomic, strong) UITextView *resultTextView;
/** rsa cryptor */
@property (nonatomic, strong) BBRSACryptor *rsaCryptor;

@end

@implementation RootViewController

- (id)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil
{
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];
    if (self) {
        // Custom initialization
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor lightGrayColor];
    // Do any additional setup after loading the view.
    
    BBRSACryptor *rsaCryptor = [[BBRSACryptor alloc] init];
    self.rsaCryptor = rsaCryptor;
    
    [self.view addSubview:self.textView];
    [self.view addSubview:self.resultTextView];
    
    float top = CGRectGetMaxY(self.textView.frame) + 10;
    {
        UIButton *_buttonT = [UIButton buttonWithType:UIButtonTypeRoundedRect];
        _buttonT.tag = 0;
        _buttonT.frame = CGRectMake(0, top, 44, 44);
        [_buttonT setTitle:@"生成密钥" forState:UIControlStateNormal];
        _buttonT.titleLabel.numberOfLines = 2;
        _buttonT.titleLabel.lineBreakMode = NSLineBreakByCharWrapping;
        _buttonT.titleLabel.font = [UIFont systemFontOfSize:15.0f];
        [_buttonT setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        [_buttonT addTarget:self
                     action:@selector(buttonTapped:)
           forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:_buttonT];
    }
    
    {
        UIButton *_buttonT = [UIButton buttonWithType:UIButtonTypeRoundedRect];
        _buttonT.tag = 1;
        _buttonT.frame = CGRectMake(44, top, 44, 44);
        [_buttonT setTitle:@"公钥加密" forState:UIControlStateNormal];
        _buttonT.titleLabel.numberOfLines = 2;
        _buttonT.titleLabel.lineBreakMode = NSLineBreakByCharWrapping;
        _buttonT.titleLabel.font = [UIFont systemFontOfSize:15.0f];
        [_buttonT setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        [_buttonT addTarget:self
                     action:@selector(buttonTapped:)
           forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:_buttonT];
    }
    
    {
        UIButton *_buttonT = [UIButton buttonWithType:UIButtonTypeRoundedRect];
        _buttonT.frame = CGRectMake(44*2, top, 44, 44);
        _buttonT.tag = 2;
        [_buttonT setTitle:@"私钥解密" forState:UIControlStateNormal];
        _buttonT.titleLabel.numberOfLines = 2;
        _buttonT.titleLabel.lineBreakMode = NSLineBreakByCharWrapping;
        _buttonT.titleLabel.font = [UIFont systemFontOfSize:15.0f];
        [_buttonT setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        [_buttonT addTarget:self
                     action:@selector(buttonTapped:)
           forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:_buttonT];
    }
    
    {
        UIButton *_buttonT = [UIButton buttonWithType:UIButtonTypeRoundedRect];
        _buttonT.frame = CGRectMake(44*3, top, 44, 44);
        _buttonT.tag = 3;
        [_buttonT setTitle:@"私钥加密" forState:UIControlStateNormal];
        _buttonT.titleLabel.numberOfLines = 2;
        _buttonT.titleLabel.lineBreakMode = NSLineBreakByCharWrapping;
        _buttonT.titleLabel.font = [UIFont systemFontOfSize:15.0f];
        [_buttonT setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        [_buttonT addTarget:self
                     action:@selector(buttonTapped:)
           forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:_buttonT];
    }
    
    {
        UIButton *_buttonT = [UIButton buttonWithType:UIButtonTypeRoundedRect];
        _buttonT.frame = CGRectMake(44*4, top, 44, 44);
        _buttonT.tag = 4;
        [_buttonT setTitle:@"公钥解密" forState:UIControlStateNormal];
        _buttonT.titleLabel.numberOfLines = 2;
        _buttonT.titleLabel.lineBreakMode = NSLineBreakByCharWrapping;
        _buttonT.titleLabel.font = [UIFont systemFontOfSize:15.0f];
        [_buttonT setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        [_buttonT addTarget:self
                     action:@selector(buttonTapped:)
           forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:_buttonT];
    }
    
    {
        UIButton *_buttonT = [UIButton buttonWithType:UIButtonTypeRoundedRect];
        _buttonT.frame = CGRectMake(44*5, top, 44, 44);
        _buttonT.tag = 5;
        [_buttonT setTitle:@"导入公钥" forState:UIControlStateNormal];
        _buttonT.titleLabel.numberOfLines = 2;
        _buttonT.titleLabel.lineBreakMode = NSLineBreakByCharWrapping;
        _buttonT.titleLabel.font = [UIFont systemFontOfSize:15.0f];
        [_buttonT setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
        [_buttonT addTarget:self
                     action:@selector(buttonTapped:)
           forControlEvents:UIControlEventTouchUpInside];
        [self.view addSubview:_buttonT];
    }
}

- (UITextView *)textView
{
    if (!_textView) {
        _textView = [[UITextView alloc] init];
        _textView.frame = CGRectMake(0, 30, 320, 80);
        _textView.backgroundColor = [UIColor whiteColor];
        _textView.delegate = self;
        _textView.font = [UIFont systemFontOfSize:15.0f];
        _textView.textColor = [UIColor blackColor];
        _textView.textAlignment = NSTextAlignmentLeft;
        _textView.editable = YES;
    }
    return _textView;
}

- (UITextView *)resultTextView
{
    if (!_resultTextView) {
        _resultTextView = [[UITextView alloc] init];
        _resultTextView.frame = CGRectMake(0, 170, 320, 250);
        _resultTextView.backgroundColor = [UIColor whiteColor];
        _resultTextView.delegate = self;
        _resultTextView.font = [UIFont systemFontOfSize:15.0f];
        _resultTextView.textColor = [UIColor blackColor];
        _resultTextView.textAlignment = NSTextAlignmentLeft;
        _resultTextView.editable = NO;
        _resultTextView.returnKeyType = UIReturnKeyDone;
    }
    return _resultTextView;
}


- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

#pragma mark ----------------------------- action

- (void)buttonTapped:(id)sender
{
    NSInteger index = [sender tag];
    
    if (index == 0)
    {
        [self.rsaCryptor generateRSAKeyPairWithKeySize:1024];
        BIGNUM *n = self.rsaCryptor->_rsa->n;
        const char *ndesc = BN_bn2hex(n);
        NSString *n_objc = [NSString stringWithCString:ndesc encoding:NSASCIIStringEncoding];
        
        BIGNUM *e = self.rsaCryptor->_rsa->e;
        const char *edesc = BN_bn2dec(e);
        NSString *e_objc = [NSString stringWithCString:edesc encoding:NSASCIIStringEncoding];
        
        BIGNUM *d = self.rsaCryptor->_rsa->d;
        const char *ddesc = BN_bn2hex(d);
        NSString *d_objc = [NSString stringWithCString:ddesc encoding:NSASCIIStringEncoding];
        
        NSString *str = [NSString stringWithFormat:@"产生长度为1024的密钥对：\n 模n:\n%@ \n 公钥指数e: %@ \n 私钥指数d:\n%@ \n 公钥base64: \n %@ \n 私钥base64: \n %@",
                         n_objc,
                         e_objc,
                         d_objc,
                         [self.rsaCryptor base64EncodedPublicKey],
                         [self.rsaCryptor base64EncodedPrivateKey]
                         ];
        
        [self appendStringToResultTextView:str];
    }
    else if (index == 1)
    {
        NSString *text = [self.textView.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        if (!text.length)
        {
            UIAlertView *alert = [[UIAlertView alloc]
                                    initWithTitle:nil
                                    message:@"请输入要被加密的明文"
                                    delegate:nil
                                    cancelButtonTitle:@"确定"
                                    otherButtonTitles:nil];
            [alert show];
            return;
        }
        
        NSData *cipherData = [self.rsaCryptor encryptWithPublicKeyUsingPadding:RSA_PKCS1_PADDING plainData:[text dataUsingEncoding:NSUTF8StringEncoding]];
        NSString *cipherString = [GTMBase64 stringByEncodingData:cipherData];
        NSString *str = [NSString stringWithFormat:@"加密后的密文的base64: \n%@", cipherString];
        [self appendStringToResultTextView:str];
    }
    else if (index == 2)
    {
        NSString *text = [self.textView.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        if (!text.length)
        {
            UIAlertView *alert = [[UIAlertView alloc]
                                  initWithTitle:nil
                                  message:@"请输入要被解密的密文"
                                  delegate:nil
                                  cancelButtonTitle:@"确定"
                                  otherButtonTitles:nil];
            [alert show];
            return;
        }
        
        NSData *cipherData = [GTMBase64 decodeString:text];
        NSData *plainData = [self.rsaCryptor decryptWithPrivateKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:cipherData];
        NSString *plainText = [[NSString alloc]initWithData:plainData encoding:NSUTF8StringEncoding];
        NSString *str = [NSString stringWithFormat:@"解密可得: \n%@", plainText];

        [self appendStringToResultTextView:str];
    }
    else if (index == 3)
    {
        NSString *text = [self.textView.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        if (!text.length)
        {
            UIAlertView *alert = [[UIAlertView alloc]
                                  initWithTitle:nil
                                  message:@"请输入要被加密的明文"
                                  delegate:nil
                                  cancelButtonTitle:@"确定"
                                  otherButtonTitles:nil];
            [alert show];
            return;
        }
        
        NSData *cipherData = [self.rsaCryptor encryptWithPrivateKeyUsingPadding:RSA_PKCS1_PADDING plainData:[text dataUsingEncoding:NSUTF8StringEncoding]];
        NSString *cipherString = [GTMBase64 stringByEncodingData:cipherData];
        NSString *str = [NSString stringWithFormat:@"加密后的密文的base64: \n%@", cipherString];
        [self appendStringToResultTextView:str];
    }
    else if (index == 4)
    {
        NSString *text = [self.textView.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        if (!text.length)
        {
            UIAlertView *alert = [[UIAlertView alloc]
                                  initWithTitle:nil
                                  message:@"请输入要被解密的密文"
                                  delegate:nil
                                  cancelButtonTitle:@"确定"
                                  otherButtonTitles:nil];
            [alert show];
            return;
        }
        
        NSData *cipherData = [GTMBase64 decodeString:text];
        NSData *plainData = [self.rsaCryptor decryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:cipherData];
        NSString *plainText = [[NSString alloc]initWithData:plainData encoding:NSUTF8StringEncoding];
        NSString *str = [NSString stringWithFormat:@"解密可得: \n%@", plainText];
        
        [self appendStringToResultTextView:str];
    }
    else if (index == 5)
    {
        NSString *text = [self.textView.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        if (!text.length)
        {
            UIAlertView *alert = [[UIAlertView alloc]
                                  initWithTitle:nil
                                  message:@"请输入公钥"
                                  delegate:nil
                                  cancelButtonTitle:@"确定"
                                  otherButtonTitles:nil];
            [alert show];
        }
        
        BOOL importSuccess = [self.rsaCryptor importRSAPublicKeyBase64:kRSAPublicKey];
        UIAlertView *alert = [[UIAlertView alloc]
                              initWithTitle:nil
                              message:importSuccess? @"导入成功":@"导入失败"
                              delegate:nil
                              cancelButtonTitle:@"确定"
                              otherButtonTitles:nil];
        [alert show];
        
//        NSData *cipherData = [GTMBase64 decodeString:text];
//        NSData *plainData = [self.rsaCryptor decryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 cipherData:cipherData];
//        NSString *plainText = [[NSString alloc]initWithData:plainData encoding:NSUTF8StringEncoding];
//        NSString *str = [NSString stringWithFormat:@"解密可得: \n%@", plainText];
//        
//        [self appendStringToResultTextView:str];
    }
}

- (void)appendStringToResultTextView:(NSString *)string
{
    NSString *now = self.resultTextView.text;
    
    now = [now stringByAppendingFormat:@"\n\n%@",string];
    
    NSRange range = NSMakeRange(now.length-1, 1);
    self.resultTextView.text = now;
    [self.resultTextView scrollRangeToVisible:range];
}

#pragma mark ----------------------------- text view

- (BOOL)textView:(UITextView *)textView shouldChangeTextInRange:(NSRange)range replacementText:(NSString *)text
{
    if ([text isEqualToString:@"\n"])
    {
        [textView resignFirstResponder];
        
//        NSString *plainText = textView.text;
//        NSData *data = [self.rsaCryptor encryptWithPublicKeyUsingPadding:RSA_PADDING_TYPE_PKCS1 plainData:[plainText dataUsingEncoding:NSUTF8StringEncoding]];
//        self.resultTextView.text = [GTMBase64 stringByEncodingData:data];
        
        return NO;
    }
    
    return YES;
}

@end
