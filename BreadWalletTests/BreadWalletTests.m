//
//  BreadWalletTests.m
//  BreadWalletTests
//
//  Created by Aaron Voisine on 5/8/13.
//  Copyright (c) 2013 Aaron Voisine <voisine@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import <XCTest/XCTest.h>
#import "BRWalletManager.h"
#import "BRBIP32Sequence.h"
#import "BRBIP39Mnemonic.h"
#import "BRTransaction.h"
#import "BRKey.h"
#import "BRKey+BIP38.h"
#import "BRBloomFilter.h"
#import "BRMerkleBlock.h"
#import "BRPaymentRequest.h"
#import "BRPaymentProtocol.h"
#import "NSData+Bitcoin.h"
#import "NSMutableData+Bitcoin.h"
#import "NSString+Bitcoin.h"

//#define SKIP_BIP38 1

@interface BreadWalletTests : XCTestCase

@end

@implementation BreadWalletTests

- (void)testBaseSeed
{
    BRBIP39Mnemonic *m = [BRBIP39Mnemonic new];
    NSString *s = @"fall very bless super monkey punch drama inside scrap dragon steak genuine";
    NSData *k = [m deriveKeyFromPhrase:s withPassphrase:nil];
    NSLog(@" entropy ? = %@",k);
    BRBIP32Sequence *seq = [BRBIP32Sequence new];
    
    NSData *new_1st = [seq getDerivedKeychainFromSeed:k WithPath:@"m/0'"];
    UInt256 secret = *(UInt256 *)new_1st.bytes;
    NSData * key_data = [NSData dataWithBytes:&secret length:sizeof(secret)];

    NSLog(@" priv key = %@",key_data);
   
    
}

- (void)testFirstAddress
{
    BRBIP39Mnemonic *m = [BRBIP39Mnemonic new];
    NSString *s = @"fall very bless super monkey punch drama inside scrap dragon steak genuine";
    NSData *k = [m deriveKeyFromPhrase:s withPassphrase:nil];
    NSLog(@" entropy ? = %@",k);
    BRBIP32Sequence *seq = [BRBIP32Sequence new];
    
    NSData *new_1st = [seq getDerivedKeychainFromSeed:k WithPath:@"m/44'/5'/0'/0/0"];
    UInt256 maza_secret = *(UInt256 *)new_1st.bytes;
    NSString *addr1 = [BRKey keyWithSecret:maza_secret compressed:YES].address;
    NSLog(@" 1st addr = %@",addr1);
    NSAssert([addr1 containsString:@"MJvB2R9bfXs3ugZ3mNfi9TXVhJuwGPCpcp"],@" First Public Address mismatch");

}
-(void)testElectrum {
    BRBIP39Mnemonic *m = [BRBIP39Mnemonic new];
    NSString *s = @"fall very bless super monkey punch drama inside scrap dragon steak genuine";
    NSData *k = [m electrumKeyFromPhrase:s withPassphrase:nil];
    //NSLog(@" entropy ? = %@",k);
    BRBIP32Sequence *seq = [BRBIP32Sequence new];
    
    NSString *priv_addr = [seq serializedPrivateMasterFromSeed:k];
    NSLog(@" seq = %@",priv_addr);

    NSAssert([priv_addr containsString:@"xprv9s21ZrQH143K2UW5avoQrASH9zvZnE2uKr6CbB4Q1aArnjMHijDgEiwuEiTcTMCn4BBPwhfa3ti1aCfkbSgBvNbnsEpe3Gmo1Jf1W8jQr7v"],@" Electrum Private Address mismatch");

     //Not seeing matching addresses with Electrum for the path
    
    NSData *new_1st = [seq getDerivedKeychainFromSeed:k WithPath:@"m/0'/0"];
    UInt256 maza_secret = *(UInt256 *)new_1st.bytes;
    NSString *addr1 = [BRKey keyWithSecret:maza_secret compressed:YES].address;
    
    NSLog(@"addr = %@",addr1);

}

- (void)setUp
{
    [super setUp];
    
    // Set-up code here.
}

- (void)tearDown
{
    // Tear-down code here.
    
    [super tearDown];
}

#pragma mark - testBase58

- (void)testBase58
{
    // test bad input
    NSString *s = [NSString base58WithData:[BTC @"#&$@*^(*#!^" base58ToData]];

    XCTAssertTrue(s.length == 0, @"[NSString base58WithData:]");
    
    s = [NSString base58WithData:[@"" base58ToData]];
    XCTAssertEqualObjects(@"", s, @"[NSString base58WithData:]");

    s = [NSString base58WithData:[@"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" base58ToData]];
    XCTAssertEqualObjects(@"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", s,
                          @"[NSString base58WithData:]");

    s = [NSString base58WithData:[@"1111111111111111111111111111111111111111111111111111111111111111111" base58ToData]];
    XCTAssertEqualObjects(@"1111111111111111111111111111111111111111111111111111111111111111111", s,
                          @"[NSString base58WithData:]");
    
    s = [NSString base58WithData:[@"111111111111111111111111111111111111111111111111111111111111111111z" base58ToData]];
    XCTAssertEqualObjects(@"111111111111111111111111111111111111111111111111111111111111111111z", s,
                          @"[NSString base58WithData:]");

    s = [NSString base58WithData:[@"z" base58ToData]];
    XCTAssertEqualObjects(@"z", s, @"[NSString base58WithData:]");
    
    s = [NSString base58checkWithData:nil];
    XCTAssertTrue(s == nil, @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"".hexToData];
    XCTAssertEqualObjects([NSData data], [s base58checkToData], @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"000000000000000000000000000000000000000000".hexToData];
    XCTAssertEqualObjects(@"000000000000000000000000000000000000000000".hexToData, [s base58checkToData],
                          @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"000000000000000000000000000000000000000001".hexToData];
    XCTAssertEqualObjects(@"000000000000000000000000000000000000000001".hexToData, [s base58checkToData],
                          @"[NSString base58checkWithData:]");

    s = [NSString base58checkWithData:@"05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".hexToData];
    XCTAssertEqualObjects(@"05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".hexToData, [s base58checkToData],
                          @"[NSString base58checkWithData:]");
}

#pragma mark - textSHA1

- (void)testSHA1
{
    UInt160 md = [@"Free online SHA1 Calculator, type text here..." dataUsingEncoding:NSUTF8StringEncoding].SHA1;
    
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"6fc2e25172cb15193cb1c6d48f607d42c1d2a215".hexToData.bytes, md),
                  @"[NSData SHA1]");
    
    md = [@"this is some text to test the sha1 implementation with more than 64bytes of data since it's internal "
          "digest buffer is 64bytes in size" dataUsingEncoding:NSUTF8StringEncoding].SHA1;
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"085194658a9235b2951a83d1b826b987e9385aa3".hexToData.bytes, md),
                  @"[NSData SHA1]");
    
    md = [@"123456789012345678901234567890123456789012345678901234567890"
          dataUsingEncoding:NSUTF8StringEncoding].SHA1;
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"245be30091fd392fe191f4bfcec22dcb30a03ae6".hexToData.bytes, md),
                  @"[NSData SHA1]");
    
    md = [@"1234567890123456789012345678901234567890123456789012345678901234"
          dataUsingEncoding:NSUTF8StringEncoding].SHA1; // a message exactly 64bytes long (internal buffer size)
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"c71490fc24aa3d19e11282da77032dd9cdb33103".hexToData.bytes, md),
                  @"[NSData SHA1]");
    
    md = [NSData data].SHA1; // empty
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"da39a3ee5e6b4b0d3255bfef95601890afd80709".hexToData.bytes, md),
                  @"[NSData SHA1]");
    
    md = [@"a" dataUsingEncoding:NSUTF8StringEncoding].SHA1;
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"86f7e437faa5a7fce15d1ddcb9eaeaea377667b8".hexToData.bytes, md),
                  @"[NSData SHA1]");
}

#pragma mark - textSHA256

- (void)testSHA256
{
    UInt256 md = [@"Free online SHA256 Calculator, type text here..." dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    
    XCTAssertTrue(uint256_eq(*(UInt256 *)
                             @"43fd9deb93f6e14d41826604514e3d7873a549ac87aebebf3d1c10ad6eb057d0".hexToData.bytes, md),
                  @"[NSData SHA256]");
    
    md = [@"this is some text to test the SHA256 implementation with more than 64bytes of data since it's internal "
          "digest buffer is 64bytes in size" dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    XCTAssertTrue(uint256_eq(*(UInt256 *)
                             @"40fd0933df2e7747f19f7d39cd30e1cb89810a7e470638a5f623669f3de9edd4".hexToData.bytes, md),
                  @"[NSData SHA256]");
    
    md = [@"123456789012345678901234567890123456789012345678901234567890"
          dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    XCTAssertTrue(uint256_eq(*(UInt256 *)
                             @"decc538c077786966ac863b5532c4027b8587ff40f6e3103379af62b44eae44d".hexToData.bytes, md),
                  @"[NSData SHA256]");
    
    md = [@"1234567890123456789012345678901234567890123456789012345678901234"
          dataUsingEncoding:NSUTF8StringEncoding].SHA256; // a message exactly 64bytes long (internal buffer size)
    XCTAssertTrue(uint256_eq(*(UInt256 *)
                             @"676491965ed3ec50cb7a63ee96315480a95c54426b0b72bca8a0d4ad1285ad55".hexToData.bytes, md),
                  @"[NSData SHA256]");
    
    md = [NSData data].SHA256; // empty
    XCTAssertTrue(uint256_eq(*(UInt256 *)
                             @"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".hexToData.bytes, md),
                  @"[NSData SHA256]");
    
    md = [@"a" dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    XCTAssertTrue(uint256_eq(*(UInt256 *)
                             @"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb".hexToData.bytes, md),
                  @"[NSData SHA256]");
}

#pragma mark - textSHA512

- (void)testSHA512
{
    UInt512 md = [@"Free online SHA512 Calculator, type text here..." dataUsingEncoding:NSUTF8StringEncoding].SHA512;

    XCTAssertTrue(uint512_eq(*(UInt512 *)@"04f1154135eecbe42e9adc8e1d532f9c607a8447b786377db8447d11a5b2232cdd419b863922"
                             "4f787a51d110f72591f96451a1bb511c4a829ed0a2ec891321f3".hexToData.bytes, md),
                  @"[NSData SHA512]");
    
    md = [@"this is some text to test the sha512 implementation with more than 128bytes of data since it's internal "
          "digest buffer is 128bytes in size" dataUsingEncoding:NSUTF8StringEncoding].SHA512;
    XCTAssertTrue(uint512_eq(*(UInt512 *)@"9bd2dc7b05fbbe9934cb3289b6e06b8ca9fd7a55e6de5db7e1e4eeddc6629b575307367cd018"
                             "3a4461d7eb2dfc6a27e41e8b70f6598ebcc7710911d4fb16a390".hexToData.bytes, md),
                  @"[NSData SHA512]");
    
    md = [@"12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"
          "8901234567890" dataUsingEncoding:NSUTF8StringEncoding].SHA512;
    XCTAssertTrue(uint512_eq(*(UInt512 *)@"0d9a7df5b6a6ad20da519effda888a7344b6c0c7adcc8e2d504b4af27aaaacd4e7111c713f71"
                             "769539629463cb58c86136c521b0414a3c0edf7dc6349c6edaf3".hexToData.bytes, md),
                  @"[NSData SHA512]");
    
    md = [@"12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"
          "890123456789012345678" dataUsingEncoding:NSUTF8StringEncoding].SHA512; //exactly 128bytes (internal buf size)
    XCTAssertTrue(uint512_eq(*(UInt512 *)@"222b2f64c285e66996769b5a03ef863cfd3b63ddb0727788291695e8fb84572e4bfe5a80674a"
                             "41fd72eeb48592c9c79f44ae992c76ed1b0d55a670a83fc99ec6".hexToData.bytes, md),
                  @"[NSData SHA512]");
    
    md = [NSData data].SHA512; // empty
    XCTAssertTrue(uint512_eq(*(UInt512 *)@"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85"
                             "f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".hexToData.bytes, md),
                  @"[NSData SHA512]");
    
    md = [@"a" dataUsingEncoding:NSUTF8StringEncoding].SHA512;
    XCTAssertTrue(uint512_eq(*(UInt512 *)@"1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf0"
                             "8d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75".hexToData.bytes, md),
                  @"[NSData SHA512]");
}

#pragma mark - testRMD160

- (void)testRMD160
{
    UInt160 md = [@"Free online RIPEMD160 Calculator, type text here..." dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"9501a56fb829132b8748f0ccc491f0ecbc7f945b".hexToData.bytes, md),
                  @"[NSData RMD160]");
    
    md = [@"this is some text to test the ripemd160 implementation with more than 64bytes of data since it's internal "
          "digest buffer is 64bytes in size" dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"4402eff42157106a5d92e4d946185856fbc50e09".hexToData.bytes, md),
                  @"[NSData RMD160]");

    md = [@"123456789012345678901234567890123456789012345678901234567890"
          dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"00263b999714e756fa5d02814b842a2634dd31ac".hexToData.bytes, md),
                  @"[NSData RMD160]");

    md = [@"1234567890123456789012345678901234567890123456789012345678901234"
          dataUsingEncoding:NSUTF8StringEncoding].RMD160; // a message exactly 64bytes long (internal buffer size)
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"fa8c1a78eb763bb97d5ea14ce9303d1ce2f33454".hexToData.bytes, md),
                  @"[NSData RMD160]");

    md = [NSData data].RMD160; // empty
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"9c1185a5c5e9fc54612808977ee8f548b2258d31".hexToData.bytes, md),
                  @"[NSData RMD160]");
    
    md = [@"a" dataUsingEncoding:NSUTF8StringEncoding].RMD160;
    XCTAssertTrue(uint160_eq(*(UInt160 *)@"0bdc9d2d256b3ee9daae347be6f4dc835a467ffe".hexToData.bytes, md),
                  @"[NSData RMD160]");
}

#pragma mark - testMD5

- (void)testMD5
{
    UInt128 md = [@"Free online MD5 Calculator, type text here..." dataUsingEncoding:NSUTF8StringEncoding].MD5;
    
    XCTAssertTrue(uint128_eq(*(UInt128 *)@"0b3b20eaf1696462f50d1a3bbdd30cef".hexToData.bytes, md), @"[NSData MD5]");
    
    md = [@"this is some text to test the md5 implementation with more than 64bytes of data since it's internal "
          "digest buffer is 64bytes in size" dataUsingEncoding:NSUTF8StringEncoding].MD5;
    XCTAssertTrue(uint128_eq(*(UInt128 *)@"56a161f24150c62d7857b7f354927ebe".hexToData.bytes, md), @"[NSData MD5]");
    
    md = [@"123456789012345678901234567890123456789012345678901234567890"
          dataUsingEncoding:NSUTF8StringEncoding].MD5;
    XCTAssertTrue(uint128_eq(*(UInt128 *)@"c5b549377c826cc3712418b064fc417e".hexToData.bytes, md), @"[NSData MD5]");
    
    md = [@"1234567890123456789012345678901234567890123456789012345678901234"
          dataUsingEncoding:NSUTF8StringEncoding].MD5; // a message exactly 64bytes long (internal buffer size)
    XCTAssertTrue(uint128_eq(*(UInt128 *)@"eb6c4179c0a7c82cc2828c1e6338e165".hexToData.bytes, md), @"[NSData MD5]");
    
    md = [NSData data].MD5; // empty
    XCTAssertTrue(uint128_eq(*(UInt128 *)@"d41d8cd98f00b204e9800998ecf8427e".hexToData.bytes, md), @"[NSData MD5]");
    
    md = [@"a" dataUsingEncoding:NSUTF8StringEncoding].MD5;
    XCTAssertTrue(uint128_eq(*(UInt128 *)@"0cc175b9c0f1b6a831c399e269772661".hexToData.bytes, md), @"[NSData MD5]");
}

#pragma mark - testKey

#if ! MAZA_TESTNET
- (void)testKeyWithPrivateKey
{
    
    // FIXME - Need good tests here!!!
#ifndef USE_MAZA
    XCTAssertFalse([@"S6c56bnXQiBjk9mqSYE7ykVQ7NzrRz" isValidMazaPrivateKey],
                  @"[NSString+Base58 isValidMazaPrivateKey]");

    // mini private key format
    XCTAssertTrue([@"S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy" isValidMazaPrivateKey],
                  @"[NSString+Base58 isValidMazaPrivateKey]");

    BRKey *key = [BRKey keyWithPrivateKey:@"S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy"];
    
    NSLog(@"privKey:S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy = %@", key.address);
    XCTAssertEqualObjects(@"1CciesT23BNionJeXrbxmjc7ywfiyM4oLW", key.address, @"[BRKey keyWithPrivateKey:]");

    // old mini private key format
    XCTAssertTrue([@"SzavMBLoXU6kDrqtUVmffv" isValidMazaPrivateKey],
                  @"[NSString+Base58 isValidMazaPrivateKey]");

    key = [BRKey keyWithPrivateKey:@"SzavMBLoXU6kDrqtUVmffv"];
    
    NSLog(@"privKey:SzavMBLoXU6kDrqtUVmffv = %@", key.address);
    XCTAssertEqualObjects(@"1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj", key.address, @"[BRKey keyWithPrivateKey:]");

    // uncompressed private key
    key = [BRKey keyWithPrivateKey:@"5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"];
    
    NSLog(@"privKey:5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF = %@", key.address);
    XCTAssertEqualObjects(@"1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj", key.address, @"[BRKey keyWithPrivateKey:]");

    // uncompressed private key export
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF", key.privateKey,
                          @"[BRKey privateKey]");

    // compressed private key
    key = [BRKey keyWithPrivateKey:@"KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL"];
    
    NSLog(@"privKey:KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL = %@", key.address);
    XCTAssertEqualObjects(@"1JMsC6fCtYWkTjPPdDrYX3we2aBrewuEM3", key.address, @"[BRKey keyWithPrivateKey:]");

    // compressed private key export
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"KyvGbxRUoofdw3TNydWn2Z78dBHSy2odn1d3wXWN2o3SAtccFNJL", key.privateKey,
                          @"[BRKey privateKey]");
    
#endif
    
}


#pragma mark - testKeyWithBIP38Key

#if ! MAZA_TESTNET && ! SKIP_BIP38
- (void)testKeyWithBIP38Key
{
#ifndef USE_MAZA
    NSString *intercode, *privkey;
    BRKey *key;

    // non EC multiplied, uncompressed
    key = [BRKey keyWithBIP38Key:@"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
           andPassphrase:@"TestingOneTwoThree"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    XCTAssertEqualObjects([key BIP38KeyWithPassphrase:@"TestingOneTwoThree"],
                          @"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
                          @"[BRKey BIP38KeyWithPassphrase:]");

    key = [BRKey keyWithBIP38Key:@"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq"
           andPassphrase:@"Satoshi"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    XCTAssertEqualObjects([key BIP38KeyWithPassphrase:@"Satoshi"],
                          @"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
                          @"[BRKey BIP38KeyWithPassphrase:]");

    // non EC multiplied, compressed
    key = [BRKey keyWithBIP38Key:@"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo"
           andPassphrase:@"TestingOneTwoThree"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    XCTAssertEqualObjects([key BIP38KeyWithPassphrase:@"TestingOneTwoThree"],
                          @"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
                          @"[BRKey BIP38KeyWithPassphrase:]");

    key = [BRKey keyWithBIP38Key:@"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7"
           andPassphrase:@"Satoshi"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    XCTAssertEqualObjects([key BIP38KeyWithPassphrase:@"Satoshi"],
                          @"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
                          @"[BRKey BIP38KeyWithPassphrase:]");

    // EC multiplied, uncompressed, no lot/sequence number
    key = [BRKey keyWithBIP38Key:@"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX"
           andPassphrase:@"TestingOneTwoThree"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    intercode = [BRKey BIP38IntermediateCodeWithSalt:0xa50dba6772cb9383 andPassphrase:@"TestingOneTwoThree"];
    NSLog(@"intercode = %@", intercode);
    privkey = [BRKey BIP38KeyWithIntermediateCode:intercode
               seedb:@"99241d58245c883896f80843d2846672d7312e6195ca1a6c".hexToData compressed:NO];
    XCTAssertEqualObjects(@"6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX", privkey,
                          @"[BRKey BIP38KeyWithIntermediateCode:]");

    key = [BRKey keyWithBIP38Key:@"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd"
           andPassphrase:@"Satoshi"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5KJ51SgxWaAYR13zd9ReMhJpwrcX47xTJh2D3fGPG9CM8vkv5sH", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    intercode = [BRKey BIP38IntermediateCodeWithSalt:0x67010a9573418906 andPassphrase:@"Satoshi"];
    NSLog(@"intercode = %@", intercode);
    privkey = [BRKey BIP38KeyWithIntermediateCode:intercode
               seedb:@"49111e301d94eab339ff9f6822ee99d9f49606db3b47a497".hexToData compressed:NO];
    XCTAssertEqualObjects(@"6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd", privkey,
                          @"[BRKey BIP38KeyWithIntermediateCode:]");

    // EC multiplied, uncompressed, with lot/sequence number
    key = [BRKey keyWithBIP38Key:@"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j"
           andPassphrase:@"MOLON LABE"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    intercode = [BRKey BIP38IntermediateCodeWithLot:263183 sequence:1 salt:0x4fca5a97u passphrase:@"MOLON LABE"];
    NSLog(@"intercode = %@", intercode);
    privkey = [BRKey BIP38KeyWithIntermediateCode:intercode
               seedb:@"87a13b07858fa753cd3ab3f1c5eafb5f12579b6c33c9a53f".hexToData compressed:NO];
    XCTAssertEqualObjects(@"6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j", privkey,
                          @"[BRKey BIP38KeyWithIntermediateCode:]");

    key = [BRKey keyWithBIP38Key:@"6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH"
           andPassphrase:@"\u039c\u039f\u039b\u03a9\u039d \u039b\u0391\u0392\u0395"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5KMKKuUmAkiNbA3DazMQiLfDq47qs8MAEThm4yL8R2PhV1ov33D", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    intercode = [BRKey BIP38IntermediateCodeWithLot:806938 sequence:1 salt:0xc40ea76fu
                 passphrase:@"\u039c\u039f\u039b\u03a9\u039d \u039b\u0391\u0392\u0395"];
    NSLog(@"intercode = %@", intercode);
    privkey = [BRKey BIP38KeyWithIntermediateCode:intercode
               seedb:@"03b06a1ea7f9219ae364560d7b985ab1fa27025aaa7e427a".hexToData compressed:NO];
    XCTAssertEqualObjects(@"6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH", privkey,
                          @"[BRKey BIP38KeyWithIntermediateCode:]");

    // password NFC unicode normalization test
    key = [BRKey keyWithBIP38Key:@"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn"
           andPassphrase:@"\u03D2\u0301\0\U00010400\U0001F4A9"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertEqualObjects(@"5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4", key.privateKey,
                          @"[BRKey keyWithBIP38Key:andPassphrase:]");
    // incorrect password test
    key = [BRKey keyWithBIP38Key:@"6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn" andPassphrase:@"foobar"];
    NSLog(@"privKey = %@", key.privateKey);
    XCTAssertNil(key, @"[BRKey keyWithBIP38Key:andPassphrase:]");
#endif
}
#endif

#endif

#pragma mark - testSign

- (void)testSign
{
    NSData *sig;
    UInt256 md, sec = *(UInt256 *)@"0000000000000000000000000000000000000000000000000000000000000001".hexToData.bytes;
    BRKey *key = [BRKey keyWithSecret:sec compressed:YES];

    md = [@"Everything should be made as simple as possible, but not simpler."
         dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key sign:md];

    XCTAssertEqualObjects(sig, @"3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c902206f80798286"
                          "6f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262".hexToData, @"[BRKey sign:]");
    XCTAssertTrue([key verify:md signature:sig], @"[BRKey verify:signature:]");
    
    sec = *(UInt256 *)@"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140".hexToData.bytes;
    key = [BRKey keyWithSecret:sec compressed:YES];
    md = [@"Equations are more important to me, because politics is for the present, but an equation is something for "
          "eternity." dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key sign:md];

    XCTAssertEqualObjects(sig, @"3044022054c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed02200708230441"
                          "0efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5".hexToData, @"[BRKey sign:]");
    XCTAssertTrue([key verify:md signature:sig], @"[BRKey verify:signature:]");

    sec = *(UInt256 *)@"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140".hexToData.bytes;
    key = [BRKey keyWithSecret:sec compressed:YES];
    md = [@"Not only is the Universe stranger than we think, it is stranger than we can think."
          dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key sign:md];

    XCTAssertEqualObjects(sig, @"3045022100ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd002206fc95f51"
                          "32e5ecfdc8e5e6e616cc77151455d46ed48f5589b7db7771a332b283".hexToData, @"[BRKey sign:]");
    XCTAssertTrue([key verify:md signature:sig], @"[BRKey verify:signature:]");

    sec = *(UInt256 *)@"0000000000000000000000000000000000000000000000000000000000000001".hexToData.bytes;
    key = [BRKey keyWithSecret:sec compressed:YES];
    md = [@"How wonderful that we have met with a paradox. Now we have some hope of making progress."
          dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key sign:md];

    XCTAssertEqualObjects(sig, @"3045022100c0dafec8251f1d5010289d210232220b03202cba34ec11fec58b3e93a85b91d3022075afdc06"
                          "b7d6322a590955bf264e7aaa155847f614d80078a90292fe205064d3".hexToData, @"[BRKey sign:]");
    XCTAssertTrue([key verify:md signature:sig], @"[BRKey verify:signature:]");

    sec = *(UInt256 *)@"69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64".hexToData.bytes;
    key = [BRKey keyWithSecret:sec compressed:YES];
    md = [@"Computer science is no more about computers than astronomy is about telescopes."
          dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key sign:md];

    XCTAssertEqualObjects(sig, @"304402207186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d02200de0b38e06"
                          "807e46bda1f1e293f4f6323e854c86d58abdd00c46c16441085df6".hexToData, @"[BRKey sign:]");
    XCTAssertTrue([key verify:md signature:sig], @"[BRKey verify:signature:]");

    sec = *(UInt256 *)@"00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637".hexToData.bytes;
    key = [BRKey keyWithSecret:sec compressed:YES];
    md = [@"...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not"
          " learning anywhere near enough" dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key sign:md];

    XCTAssertEqualObjects(sig, @"3045022100fbfe5076a15860ba8ed00e75e9bd22e05d230f02a936b653eb55b61c99dda48702200e68880e"
                          "bb0050fe4312b1b1eb0899e1b82da89baa5b895f612619edf34cbd37".hexToData, @"[BRKey sign:]");
    XCTAssertTrue([key verify:md signature:sig], @"[BRKey verify:signature:]");

    sec = *(UInt256 *)@"000000000000000000000000000000000000000000056916d0f9b31dc9b637f3".hexToData.bytes;
    key = [BRKey keyWithSecret:sec compressed:YES];
    md = [@"The question of whether computers can think is like the question of whether submarines can swim."
          dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key sign:md];

    XCTAssertEqualObjects(sig, @"3045022100cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf9022006ce643f"
                          "5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef".hexToData, @"[BRKey sign:]");
    XCTAssertTrue([key verify:md signature:sig], @"[BRKey verify:signature:]");
}

#pragma mark - testCompactSign

- (void)testCompactSign
{
    NSData *pubkey, *sig;
    UInt256 md, sec = *(UInt256 *)@"0000000000000000000000000000000000000000000000000000000000000001".hexToData.bytes;
    BRKey *key;
    
    key = [BRKey keyWithSecret:sec compressed:YES];
    md = [@"foo" dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key compactSign:md];
    pubkey = [BRKey keyRecoveredFromCompactSig:sig andMessageDigest:md].publicKey;
    
    XCTAssertEqualObjects(key.publicKey, pubkey);

    key = [BRKey keyWithSecret:sec compressed:NO];
    md = [@"foo" dataUsingEncoding:NSUTF8StringEncoding].SHA256;
    sig = [key compactSign:md];
    pubkey = [BRKey keyRecoveredFromCompactSig:sig andMessageDigest:md].publicKey;
    
    XCTAssertEqualObjects(key.publicKey, pubkey);

    pubkey = @"26wZYDdvpmCrYZeUcxgqd1KquN4o6wXwLomBW5SjnwUqG".base58ToData;
    md = [@"i am a test signed string" dataUsingEncoding:NSUTF8StringEncoding].SHA256_2;
    sig = @"3kq9e842BzkMfbPSbhKVwGZgspDSkz4YfqjdBYQPWDzqd77gPgR1zq4XG7KtAL5DZTcfFFs2iph4urNyXeBkXsEYY".base58ToData;
    key = [BRKey keyRecoveredFromCompactSig:sig andMessageDigest:md];

    XCTAssertEqualObjects(key.publicKey, pubkey);

    pubkey = @"26wZYDdvpmCrYZeUcxgqd1KquN4o6wXwLomBW5SjnwUqG".base58ToData;
    md = [@"i am a test signed string do de dah" dataUsingEncoding:NSUTF8StringEncoding].SHA256_2;
    sig = @"3qECEYmb6x4X22sH98Aer68SdfrLwtqvb5Ncv7EqKmzbxeYYJ1hU9irP6R5PeCctCPYo5KQiWFgoJ3H5MkuX18gHu".base58ToData;
    key = [BRKey keyRecoveredFromCompactSig:sig andMessageDigest:md];

    XCTAssertEqualObjects(key.publicKey, pubkey);

    pubkey = @"gpRv1sNA3XURB6QEtGrx6Q18DZ5cSgUSDQKX4yYypxpW".base58ToData;
    md = [@"i am a test signed string" dataUsingEncoding:NSUTF8StringEncoding].SHA256_2;
    sig = @"3oHQhxq5eW8dnp7DquTCbA5tECoNx7ubyiubw4kiFm7wXJF916SZVykFzb8rB1K6dEu7mLspBWbBEJyYk79jAosVR".base58ToData;
    key = [BRKey keyRecoveredFromCompactSig:sig andMessageDigest:md];
    
    XCTAssertEqualObjects(key.publicKey, pubkey);
}

#pragma mark - testPaymentRequest

//TODO: test valid request with unknown arguments
//TODO: test invalid address
//TODO: test invalid request with unknown required arguments

- (void)testPaymentRequest
{
    BRPaymentRequest *r = [BRPaymentRequest requestWithString:@"1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW"];
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    r = [BRPaymentRequest requestWithString:@"1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQ"];
    XCTAssertFalse(r.isValid);
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQ", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW"];
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW", r.string,
                          @"[BRPaymentRequest requestWithString:]");
    
    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=1"];
    XCTAssertEqual(100000000, r.amount, @"[BRPaymentRequest requestWithString:]");
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=1", r.string,
                          @"[BRPaymentRequest requestWithString:]");
    
    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=0.00000001"];
    XCTAssertEqual(1, r.amount, @"[BRPaymentRequest requestWithString:]");
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=0.00000001", r.string,
                          @"[BRPaymentRequest requestWithString:]");
    
    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=21000000"];
    XCTAssertEqual(2100000000000000, r.amount, @"[BRPaymentRequest requestWithString:]");
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=21000000", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    // test for floating point rounding issues, these values cannot be exactly represented with an IEEE 754 double
    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=20999999.99999999"];
    XCTAssertEqual(2099999999999999, r.amount, @"[BRPaymentRequest requestWithString:]");
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=20999999.99999999", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=20999999.99999995"];
    XCTAssertEqual(2099999999999995, r.amount, @"[BRPaymentRequest requestWithString:]");
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=20999999.99999995", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=20999999.9999999"];
    XCTAssertEqual(2099999999999990, r.amount, @"[BRPaymentRequest requestWithString:]");
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=20999999.9999999", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=0.07433"];
    XCTAssertEqual(7433000, r.amount, @"[BRPaymentRequest requestWithString:]");
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=0.07433", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    // invalid amount string
    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?amount=foobar"];
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    // test correct encoding of '&' in argument value
    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?label=foo%26bar"];
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?label=foo%26bar", r.string,
                          @"[BRPaymentRequest requestWithString:]");
    
    // test handling of ' ' in label or message
    r = [BRPaymentRequest
         requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?label=foo bar&message=bar foo"];
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?label=foo%20bar&message=bar%20foo", r.string,
                          @"[BRPaymentRequest requestWithString:]");
    
    // test bip73
    r = [BRPaymentRequest requestWithString:@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?r=https://foobar.com"];
    XCTAssertEqualObjects(@"maza:1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW?r=https://foobar.com", r.string,
                          @"[BRPaymentRequest requestWithString:]");

    r = [BRPaymentRequest requestWithString:@"maza:?r=https://foobar.com"];
    XCTAssertTrue(r.isValid);
    XCTAssertEqualObjects(@"maza:?r=https://foobar.com", r.string, @"[BRPaymentRequest requestWithString:]");
}

#pragma mark - testTransaction

- (void)testTransaction
{
    NSMutableData *script = [NSMutableData data];
    UInt256 secret = *(UInt256 *)@"0000000000000000000000000000000000000000000000000000000000000001".hexToData.bytes;
    BRKey *k = [BRKey keyWithSecret:secret compressed:YES];
    NSValue *hash = uint256_obj(UINT256_ZERO);

    [script appendScriptPubKeyForAddress:k.address];

    BRTransaction *tx = [[BRTransaction alloc] initWithInputHashes:@[hash] inputIndexes:@[@0] inputScripts:@[script]
                         outputAddresses:@[k.address, k.address] outputAmounts:@[@100000000, @4900000000]];

    [tx signWithPrivateKeys:@[k.privateKey]];

    XCTAssertTrue([tx isSigned], @"[BRTransaction signWithPrivateKeys:]");

    NSUInteger height = [tx blockHeightUntilFreeForAmounts:@[@5000000000] withBlockHeights:@[@1]];
    uint64_t priority = [tx priorityForAmounts:@[@5000000000] withAges:@[@(height - 1)]];
    
    NSLog(@"height = %lu", (unsigned long)height);
    NSLog(@"priority = %llu", priority);
    
    XCTAssertTrue(priority >= TX_FREE_MIN_PRIORITY, @"[BRTransaction priorityForAmounts:withAges:]");

    NSData *d = tx.data;

    tx = [BRTransaction transactionWithMessage:d];

    XCTAssertEqualObjects(d, tx.data, @"[BRTransaction transactionWithMessage:]");

    tx = [[BRTransaction alloc] initWithInputHashes:@[hash, hash, hash, hash, hash, hash, hash, hash, hash, hash]
          inputIndexes:@[@0, @0,@0, @0, @0, @0, @0, @0, @0, @0]
          inputScripts:@[script, script, script, script, script, script, script, script, script, script]
          outputAddresses:@[k.address, k.address, k.address, k.address, k.address, k.address, k.address, k.address,
                            k.address, k.address]
          outputAmounts:@[@1000000, @1000000, @1000000, @1000000, @1000000, @1000000, @1000000, @1000000, @1000000,
                          @1000000]];

    [tx signWithPrivateKeys:@[k.privateKey]];

    XCTAssertTrue([tx isSigned], @"[BRTransaction signWithPrivateKeys:]");

    height = [tx blockHeightUntilFreeForAmounts:@[@1000000, @1000000, @1000000, @1000000, @1000000, @1000000, @1000000,
                                                  @1000000, @1000000, @1000000]
              withBlockHeights:@[@1, @2, @3, @4, @5, @6, @7, @8, @9, @10]];
    priority = [tx priorityForAmounts:@[@1000000, @1000000, @1000000, @1000000, @1000000, @1000000, @1000000, @1000000,
                                        @1000000, @1000000]
                withAges:@[@(height - 1), @(height - 2), @(height - 3), @(height - 4), @(height - 5), @(height - 6),
                           @(height - 7), @(height - 8), @(height - 9), @(height - 10)]];
    
    NSLog(@"height = %lu", (unsigned long)height);
    NSLog(@"priority = %llu", priority);
    
    XCTAssertTrue(priority >= TX_FREE_MIN_PRIORITY, @"[BRTransaction priorityForAmounts:withAges:]");
    
    d = tx.data;
    tx = [BRTransaction transactionWithMessage:d];

    XCTAssertEqualObjects(d, tx.data, @"[BRTransaction transactionWithMessage:]");
}

#pragma mark - testBIP39Mnemonic



- (void)testBIP39MnemonicFind
{
    BRBIP39Mnemonic *m = [BRBIP39Mnemonic new];
    int i=2048-16;
    NSString *word_list;
    do {
        NSString *s = @"apart wide short nothing enter before again off tree road country ";
        word_list = [s stringByAppendingString:[m getWordAtIndex:i]];
        i++;
    } while (![m phraseIsValid:word_list]);
    
    NSLog(@" checksum word is %@",[m getWordAtIndex:(i-1)]);
}

- (void)testBIP39Mnemonic
{
    BRBIP39Mnemonic *m = [BRBIP39Mnemonic new];
    NSString *s = @"bless cloud wheel regular tiny venue bird web grief security dignity zoo";
    NSData *d, *k;

    XCTAssertFalse([m phraseIsValid:s], @"[BRMnemonic phraseIsValid:]"); // test correct handling of bad checksum
    XCTAssertNil([m normalizePhrase:nil]);
    XCTAssertNil([m deriveKeyFromPhrase:nil withPassphrase:nil]);

    d = @"00000000000000000000000000000000".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                          "about", @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c9"
                          "2f2cf141630c7a3c4ab7c81b2f001698e7463b04".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"legal winner thank year wave sausage worth useful legal winner thank yellow",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937"
                          "a1c1069be3a3a5bd381ee6260e8d9739fce1f607".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"80808080808080808080808080808080".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c"
                          "462a0358d18d69fe4f985ec81778c1b370b652a8".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"ffffffffffffffffffffffffffffffff".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6"
                          "f15b11c61dee327651a14c34e18231052e48c069".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"000000000000000000000000000000000000000000000000".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                          "abandon abandon abandon abandon abandon abandon agent",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b"
                          "844d8a71dd9f439c52a3d7b3e8a79c906ac845fa".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"legal winner thank year wave sausage worth useful legal winner thank year wave sausage "
                          "worth useful legal will",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612"
                          "bada0753b52a1c7ac53c1e93abd5c6320b9e95dd".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"808080808080808080808080808080808080808080808080".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount "
                          "doctor acoustic avoid letter always",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33"
                          "b610cf0e91d3aa239027f5e99fe4ce9e5088cd65".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"ffffffffffffffffffffffffffffffffffffffffffffffff".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd1"
                          "29090758b3e3c2c49103b5051aac2eaeb890a528".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"0000000000000000000000000000000000000000000000000000000000000000".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                          "abandon art", @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8"
                          "d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"legal winner thank year wave sausage worth useful legal winner thank year wave sausage "
                          "worth useful legal winner thank year wave sausage worth title",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb"
                          "835f43620bf5c514db0f8add49f5d121449d3e87".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"8080808080808080808080808080808080808080808080808080808080808080".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount "
                          "doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df4300"
                          "22f7a2b6fb91661a9589097069720d015e4e982f".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
                          "zoo vote", @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd"
                          "31ed3992c456cdf60f5d4564b8ba3f05a69890ad".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"77c2b00716cec7213839159e404db50d".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf"
                          "2d602c051f3e6f18055e84e4c43897fc4e51a6ff".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"renew stay biology evidence goat welcome casual join adapt armor shuffle fault little "
                          "machine walk stumble urge swap",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941c69e1bdbf2966e0f6"
                          "e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk "
                          "host tomato cradle drill spread actor shine dismiss champion exotic",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"ff7f3184df8696d8bef94b6c03114dbee0ef89ff938712301d27ed8336ca89ef9635da20af07d4175f2bf5f3"
                          "de130f39c9d9e8dd0472489c19b1a020a940da67".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"0460ef47585604c5660618db2e6a7e7f".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"afford alter spike radar gate glance object seek swamp infant panel yellow",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"65f93a9f36b6c85cbe634ffc1f99f2b82cbb10b31edc7f087b4f6cb9e976e9faf76ff41f8f27c99afdf38f7a"
                          "303ba1136ee48a4c1e7fcd3dba7aa876113a36e4".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme "
                          "poem divorce alter left",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"3bbf9daa0dfad8229786ace5ddb4e00fa98a044ae4c4975ffd5e094dba9e0bb289349dbe2091761f30f382d4"
                          "e35c4a670ee8ab50758d2c55881be69e327117ba".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open "
                          "hour vintage deposit universe tip job dress radar refuse motion taste",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"fe908f96f46668b2d5b37d82f558c77ed0d69dd0e7e043a5b0511c48c2f1064694a956f86360c93dd04052a8"
                          "899497ce9e985ebe0c8c52b955e6ae86d4ff4449".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"eaebabb2383351fd31d703840b32e9e2".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"turtle front uncle idea crush write shrug there lottery flower risk shell",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95e"
                          "f3ca1e5146646856c461c073169467511680876c".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"kiss carry display unusual confirm curtain upgrade antique rotate hello void custom "
                          "frequent obey nut hole price segment", @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"ed56ff6c833c07982eb7119a8f48fd363c4a9b1601cd2de736b01045c5eb8ab4f57b079403485d1c4924f079"
                          "0dc10a971763337cb9f9c62226f64fff26397c79".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end "
                          "lucky hurt sentence oven short ball bird grab wing top", @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"095ee6f817b4c2cb30a5a797360a81a40ab0f9a4e25ecd672a3f58a0b5ba0687c096a6b14d2c0deb3bdefce4"
                          "f61d01ae07417d502429352e27695163f7447a8c".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"18ab19a9f54a9274f03e5209a2ac8a91".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"board flee heavy tunnel powder denial science ski answer betray cargo cat",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"6eff1bb21562918509c73cb990260db07c0ce34ff0e3cc4a8cb3276129fbcb300bddfe005831350efd633909"
                          "f476c45c88253276d9fd0df6ef48609e8bb7dca8".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"board blade invite damage undo sun mimic interest slam gaze truly inherit resist great "
                          "inject rocket museum chief", @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"f84521c777a13b61564234bf8f8b62b3afce27fc4062b51bb5e62bdfecb23864ee6ecf07c1d5a97c0834307c"
                          "5c852d8ceb88e7c97923c0a3b496bedd4e5f88a9".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    d = @"15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419".hexToData;
    s = [m encodePhrase:d];
    k = [m deriveKeyFromPhrase:s withPassphrase:@"TREZOR"];
    XCTAssertEqualObjects(d, [m decodePhrase:s], @"[BRBIP39Mnemonic decodePhrase:]");
    XCTAssertEqualObjects(s, @"beyond stage sleep clip because twist token leaf atom beauty genius food business side "
                          "grid unable middle armed observe pair crouch tonight away coconut",
                          @"[BRBIP39Mnemonic encodePhrase:]");
    XCTAssertEqualObjects(k, @"b15509eaa2d09d3efd3e006ef42151b30367dc6e3aa5e44caba3fe4d3e352e65101fbdb86a96776b91946ff0"
                          "6f8eac594dc6ee1d3e82a42dfe1b40fef6bcc3fd".hexToData,
                          @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");

    NSString *words_nfkd = @"Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c "
                           "u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 "
                           "uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a";
    NSString *words_nfc = @"P\u0159\u00ed\u0161ern\u011b \u017elu\u0165ou\u010dk\u00fd k\u016f\u0148 \u00fap\u011bl "
                          "\u010f\u00e1belsk\u00e9 \u00f3dy z\u00e1ke\u0159n\u00fd u\u010de\u0148 b\u011b\u017e\u00ed "
                          "pod\u00e9l z\u00f3ny \u00fal\u016f";
    NSString *words_nfkc = @"P\u0159\u00ed\u0161ern\u011b \u017elu\u0165ou\u010dk\u00fd k\u016f\u0148 \u00fap\u011bl "
                           "\u010f\u00e1belsk\u00e9 \u00f3dy z\u00e1ke\u0159n\u00fd u\u010de\u0148 b\u011b\u017e\u00ed "
                           "pod\u00e9l z\u00f3ny \u00fal\u016f";
    NSString *words_nfd = @"Pr\u030ci\u0301s\u030cerne\u030c z\u030clut\u030couc\u030cky\u0301 ku\u030an\u030c "
                          "u\u0301pe\u030cl d\u030ca\u0301belske\u0301 o\u0301dy za\u0301ker\u030cny\u0301 "
                          "uc\u030cen\u030c be\u030cz\u030ci\u0301 pode\u0301l zo\u0301ny u\u0301lu\u030a";
    NSString *passphrase_nfkd = @"Neuve\u030cr\u030citelne\u030c bezpec\u030cne\u0301 hesli\u0301c\u030cko";
    NSString *passphrase_nfc = @"Neuv\u011b\u0159iteln\u011b bezpe\u010dn\u00e9 hesl\u00ed\u010dko";
    NSString *passphrase_nfkc = @"Neuv\u011b\u0159iteln\u011b bezpe\u010dn\u00e9 hesl\u00ed\u010dko";
    NSString *passphrase_nfd = @"Neuve\u030cr\u030citelne\u030c bezpec\u030cne\u0301 hesli\u0301c\u030cko";
    NSData *seed_nfkd = [m deriveKeyFromPhrase:words_nfkd withPassphrase:passphrase_nfkd];
    NSData *seed_nfc = [m deriveKeyFromPhrase:words_nfc withPassphrase:passphrase_nfc];
    NSData *seed_nfkc = [m deriveKeyFromPhrase:words_nfkc withPassphrase:passphrase_nfkc];
    NSData *seed_nfd = [m deriveKeyFromPhrase:words_nfd withPassphrase:passphrase_nfd];

    // test multiple different unicode representations of the same phrase
    XCTAssertEqualObjects(seed_nfkd, seed_nfc, @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");
    XCTAssertEqualObjects(seed_nfkd, seed_nfkc, @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");
    XCTAssertEqualObjects(seed_nfkd, seed_nfd, @"[BRBIP39Mnemonic deriveKeyFromPhrase: withPassphrase:]");
}

#pragma mark - testBIP32Sequence

#ifndef USE_MAZA
#if ! MAZA_TESTNET
- (void)testBIP32SequencePrivateKey
{
    BRBIP32Sequence *seq = [BRBIP32Sequence new];
    NSData *seed = @"000102030405060708090a0b0c0d0e0f".hexToData;
    NSString *pk = [seq privateKey:2 | 0x80000000 internal:YES fromSeed:seed];
    NSData *d = pk.base58checkToData;

    NSLog(@"000102030405060708090a0b0c0d0e0f/0'/1/2' prv = %@", [NSString hexWithData:d]);


    XCTAssertEqualObjects(d, @"80cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca01".hexToData,
                         @"[BRBIP32Sequence privateKey:internal:fromSeed:]");

    // Test for correct zero padding of private keys, a nasty potential bug
    pk = [seq privateKey:97 internal:NO fromSeed:seed];
    d = pk.base58checkToData;

    NSLog(@"000102030405060708090a0b0c0d0e0f/0'/0/97 prv = %@", [NSString hexWithData:d]);

    XCTAssertEqualObjects(d, @"8000136c1ad038f9a00871895322a487ed14f1cdc4d22ad351cfa1a0d235975dd701".hexToData,
                         @"[BRBIP32Sequence privateKey:internal:fromSeed:]");
}
#endif

- (void)testBIP32SequenceMasterPublicKeyFromSeed
{
    BRBIP32Sequence *seq = [BRBIP32Sequence new];
    NSData *seed = @"000102030405060708090a0b0c0d0e0f".hexToData;
    NSData *mpk = [seq masterPublicKeyFromSeed:seed];
    
    NSLog(@"000102030405060708090a0b0c0d0e0f/0' pub+chain = %@", [NSString hexWithData:mpk]);
    
    XCTAssertEqualObjects(mpk, @"3442193e"
                               "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
                               "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56".hexToData,
                         @"[BRBIP32Sequence masterPublicKeyFromSeed:]");
}

- (void)testBIP32SequencePublicKey
{
    BRBIP32Sequence *seq = [BRBIP32Sequence new];
    NSData *seed = @"000102030405060708090a0b0c0d0e0f".hexToData;
    NSData *mpk = [seq masterPublicKeyFromSeed:seed];
    NSData *pub = [seq publicKey:0 internal:NO masterPublicKey:mpk];

    NSLog(@"000102030405060708090a0b0c0d0e0f/0'/0/0 pub = %@", [NSString hexWithData:pub]);
    
    XCTAssertEqualObjects(pub, @"027b6a7dd645507d775215a9035be06700e1ed8c541da9351b4bd14bd50ab61428".hexToData,
                          @"[BRBIP32Sequence publicKey:internal:masterPublicKey:]");
}

#pragma mark - testWallet

//TODO: test standard free transaction no change
//TODO: test free transaction who's inputs are too new to hit min free priority
//TODO: test transaction with change below min allowable output
//TODO: test gap limit with gaps in address chain less than the limit
//TODO: test removing a transaction that other transansactions depend on
//TODO: test tx ordering for multiple tx with same block height
//TODO: port all applicable tests from bitcoinj and bitcoincore

#ifdef USE_MAZA
- (void)testWallet
{
    NSMutableData *script = [NSMutableData data];
    UInt256 secret = *(UInt256 *)@"0000000000000000000000000000000000000000000000000000000000000001".hexToData.bytes;
    BRKey *k = [BRKey keyWithSecret:secret compressed:YES];
    NSValue *hash = uint256_obj(UINT256_ZERO);
    BRWallet *w = [[BRWallet alloc] initWithContext:nil sequence:[BRBIP32Sequence new] masterPublicKey:nil
                   seed:^NSData *(NSString *authprompt, uint64_t amount) { return [NSData data]; }];

    [script appendScriptPubKeyForAddress:k.address];

    BRTransaction *tx = [[BRTransaction alloc] initWithInputHashes:@[hash] inputIndexes:@[@(0)] inputScripts:@[script]
                         outputAddresses:@[w.receiveAddress] outputAmounts:@[@(SATOSHIS)]];

    [tx signWithPrivateKeys:@[k.privateKey]];
    [w registerTransaction:tx];

    XCTAssertEqual(w.balance, SATOSHIS, @"[BRWallet registerTransaction]");

    tx = [w transactionFor:SATOSHIS/2 to:k.address withFee:NO];

    XCTAssertNotNil(tx, @"[BRWallet transactionFor:to:withFee:]");

    [w signTransaction:tx withPrompt:nil];

    XCTAssertTrue(tx.isSigned, @"[BRWallet signTransaction]");

    [w registerTransaction:tx];

    XCTAssertEqual(w.balance, SATOSHIS/2, @"[BRWallet balance]");

#if ! MAZA_TESTNET
    w = [[BRWallet alloc] initWithContext:nil sequence:[BRBIP32Sequence new] masterPublicKey:nil
         seed:^NSData *(NSString *authprompt, uint64_t amount) { return [NSData data]; }];
    
    NSMutableSet *allAddresses = (id)w.addresses;

    [allAddresses addObject:@"1DjJGdMuW6UKunUS3jAuaEcqZ2mkH1QNHc"];
    [allAddresses addObject:@"1P5hsxGtGYEftqcP7gY63pKX7JXCfLCNiR"];
    [allAddresses addObject:@"1htJNo75xgfHUYA7ag8hRMjwg5mREfkD7"];
    [allAddresses addObject:@"19UZQkmaH4PqE99t5bPgA83HeXJAkoogKE"];
    [allAddresses addObject:@"18fPNnWxGhytebu2or4c2tFcnkXVeB2aL6"];
    [allAddresses addObject:@"16XP5vHKm2qnQHAGpmUBCwzGVxamDbGQ5N"];
    [allAddresses addObject:@"1DieDrnPmjv4TfxXukZTKsm32PgFfwKcFA"];

    [w registerTransaction:[BRTransaction transactionWithMessage:@"0100000001932bcd947e72ed69b813a7afc6a75a97bc60a26e45"
     "e2635ca6b5b619cf650d84010000006a4730440220697f9338ecc869361094bc6ab5243cbf683a84e3f424599e3b2961dd33e018f602202a6"
     "190a65b7ac42c9a907823e11e28991c01dd1bda7081bc99191c8304481c5501210235c032e32c490055212aecba58526a68f2ce3d0e53388c"
     "e01efe1764214f52dbffffffff02a0860100000000001976a914b1cedc0e005cb1e929e18b14a2cbb481d4b7e65d88aca0ad3900000000001"
     "976a9148ba16545a88d500197281540541299394194a17a88ac00000000".hexToData]];
    [w registerTransaction:[BRTransaction transactionWithMessage:@"0100000001669313d613ee6b9e31252b7d4160ab821ab21cf059"
     "b7d7b8a5b4c29ebba45d30000000006b483045022100e1e314053d86aff56b4bda7aab3b650732e7d8da6e79f7ab23c1fc4523c44f0d02202"
     "a55fce6cad078ac801626fcd42c40ff43692ade3fe14cfb97f685c070dfe9ea012102ce4f2739e0acf7e6c2eb5babf6cc62d44e5de70ba1a5"
     "9274af86bd5c1c9fa404ffffffff01301b0f00000000001976a914f2368e03acc87480f355dd917baca95e5d19e74d88ac00000000"
     "".hexToData]];
    [w registerTransaction:[BRTransaction transactionWithMessage:@"01000000011000b4ec5446e9d45c04fec06774468d003db4f662"
     "0df256a22ffd6d79883688000000008a473044022022afda9e3a3589c9b286f0c6a989374f59b8c217e0de127bec612265a2b0749b022050f"
     "dc59045592eae7aad218d0f2ac14a7f410a9195018ceecb50e6fc92060526014104a3be6b242cfbef34e63002f304eceb058fdc36797241c3"
     "78b06fa44573e5307031cf1a4c3a1caeac128abfedd169f02db1e795788d27ff44a81a32c50645ab7cffffffff01d06c0400000000001976a"
     "91407bb76119e91184e49882b168e5c785ecefb5b2488ac00000000".hexToData]];
    [w registerTransaction:[BRTransaction transactionWithMessage:@"010000000104c58782c504726fa26c26b23d6cae4715311fb6db"
     "d9ff494f5868cc0686948b010000008a47304402207643b8852c93e425d5a41b8e6e9126cce85115fe99310b680b86c69852dd386e0220691"
     "da90f76fb4ee9519edf2afe4aa0f04d44529bf8602b00c4f31aad7d631d37014104126989db35c5088c021ef16a0d67b1cda7dac2dee20144"
     "ff95b543b449788e5a66c6f314981dd0baffaa5057d5b972e4fb274e2799d6bae796ed2c29be97c574ffffffff0280969800000000001976a"
     "9145cf74a97cf524c5b99a6ec29f3ab3ed4b436592988ac49981700000000001976a9148e022fdce38b1d22fb5bfe89d3e8256c650f246988"
     "ac00000000".hexToData]];
    [w registerTransaction:[BRTransaction transactionWithMessage:@"01000000011000b4ec5446e9d45c04fec06774468d003db4f662"
     "0df256a22ffd6d79883688010000008b483045022100d77a298b3126b347d1576e301ba7a6ca0610124f2cb0cc47b58254cb66cbd00302205"
     "3708a6c858dfb35a65b57381fec99e5797c33cc7d66d220469564303a62dc8a014104a331cd33c13ba323e549fdefa11af1f03f86a44a4f2e"
     "e0883fab39d96bf9c147940afe36e2ddf6ebbef5e8a57a931d5f854abcc27b33d1ba7f424647202a7ee2ffffffff0240420f0000000000197"
     "6a914540b5d80a4d05a2cf7035bbca524f68ef93cf79688ac60926200000000001976a914bf49bd44526f6ab157275aa938df9479bfecf003"
     "88ac00000000".hexToData]];
    [w registerTransaction:[BRTransaction transactionWithMessage:@"0100000002f6d5012856206e93341a40b19afb86caabe9964753"
     "99b77d3695f484ec6fb1d4000000006b483045022100d0f7d86aea22a4fe23bb3b5de29e56983faa9fdf60052a0d8321212ca972336502201"
     "09b11f128e24a2d3dc615ddf2124bb2d1e7506a80a944bafa5ebdf965043982012102fe5d33b9a5fe9c8799d6f8ad0cf92bd477620dd299c5"
     "62c812295dcb6d66f6b4ffffffffe9c01e3b016c95729b13fa5db25412c89a555223f6d4378c3b65898e5b3ca8dd000000006b48304502210"
     "092e5b28aea395ca4a916067ac18f30a9616d6cf827158e80126a657152226165022043cb34077eaf4ec01727eeb038b0b297da0c5580beb1"
     "11b999949c36ba53d12301210382efead48069b88d35ea13e0e80f19eda6c08191f1ce668a77c8d210c5791ffeffffffff0240420f0000000"
     "0001976a914faaaeb7f7e534ee2e18c3f15a3191dd51c36a93688ac5f700c00000000001976a9143c978b11b19d0718b4a847304340b3804d"
     "5194a388ac00000000".hexToData]];
    [w registerTransaction:[BRTransaction transactionWithMessage:@"01000000027560f62fa95ecdb9eb0bf200764b8eff99c717918c"
     "743314fe1e7d4dc9899cc8010000008a47304402203e2c3beb755fe868728896482aaa197f10c4bad9749e9f4d9e607acd23726b9602202bb"
     "0eca3031ee8c750a6688f02b422275b0b02f4353c3e9526905e297c7e2ca801410429c3b9fa9ec9aea0918ccc00c08a814f13bdd2e72273b6"
     "2b046605f8daa8b559b2aec4706caa15b914897ea3be4ba3b200aeca22f16ed882836cad0bdf9c282affffffff8b10474e40d60efc2612614"
     "97ed6d46d38e5219fce122c1ba2b0bc645342fef3000000008a47304402202990aa1fcbb519bf6edd798f6290930bd8c0e8e6185153af0b90"
     "ed64249302c20220419a07a674753778ab2198f37f43b2c7f7c3ef2aac8b685090e30484a366cf960141049b3707c1b05412511a75eaa39b2"
     "56bc7e958539e66fd02b291199df0408c62bbe70a093560cc408e52fac7ee74ed650c5f8c70b85ccc9a2ab853164d1d2a4bd3ffffffff0240"
     "548900000000001976a9148b81a28bc33e75484783475aed1f1e78ac4c084788acbe040300000000001976a9146a5af3e825f69bec5089b42"
     "f54c389c19673ba8488ac00000000".hexToData]];

    // larger than 1k transaction
    tx = [w transactionFor:25000000 to:@"16c7nyuu2D99LqJ8TQ8GSsWSyrCYDS5qBA" withFee:YES];
    NSLog(@"fee: %llu, should be %llu", [w feeForTransaction:tx], [w feeForTxSize:tx.size + 1965]);

    int64_t amount = [w amountReceivedFromTransaction:tx] - [w amountSentByTransaction:tx],
            fee = [w feeForTxSize:tx.size + 1965] + ((w.balance - 25000000) % 100);

    XCTAssertEqual([w feeForTransaction:tx], fee, @"[BRWallet transactionFor:to:withFee:]");
    XCTAssertEqual(amount, -25000000 - fee);
#endif

    XCTAssertEqual([w feeForTxSize:tx.size], tx.standardFee, @"[BRWallet feeForTxSize:]");
}
#endif
#endif

#pragma mark - testWalletManager

- (void)testWalletManager
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    NSString *s;
    
    XCTAssertEqual([manager amountForString:nil], 0, @"[BRWalletManager amountForString:]");
    
    XCTAssertEqual([manager amountForString:@""], 0, @"[BRWalletManager amountForString:]");

    s = [manager stringForAmount:0];
    XCTAssertEqual([manager amountForString:s], 0, @"[BRWalletManager amountForString:]");
    
    s = [manager stringForAmount:100000000];
    XCTAssertEqual([manager amountForString:s], 100000000, @"[BRWalletManager amountForString:]");

    s = [manager stringForAmount:1];
    XCTAssertEqual([manager amountForString:s], 1, @"[BRWalletManager amountForString:]");
    
    s = [manager stringForAmount:2100000000000000];
    XCTAssertEqual([manager amountForString:s], 2100000000000000, @"[BRWalletManager amountForString:]");
    
    s = [manager stringForAmount:2099999999999999];
    XCTAssertEqual([manager amountForString:s], 2099999999999999, @"[BRWalletManager amountForString:]");
    
    s = [manager stringForAmount:2099999999999995];
    XCTAssertEqual([manager amountForString:s], 2099999999999995, @"[BRWalletManager amountForString:]");
    
    s = [manager stringForAmount:2099999999999990];
    XCTAssertEqual([manager amountForString:s], 2099999999999990, @"[BRWalletManager amountForString:]");
}

#pragma mark - testBloomFilter

- (void)testBloomFilter
{
    BRBloomFilter *f = [[BRBloomFilter alloc] initWithFalsePositiveRate:.01 forElementCount:3 tweak:0
                        flags:BLOOM_UPDATE_ALL];

    [f insertData:@"99108ad8ed9bb6274d3980bab5a85c048f0950c8".hexToData];

    XCTAssertTrue([f containsData:@"99108ad8ed9bb6274d3980bab5a85c048f0950c8".hexToData],
                 @"[BRBloomFilter containsData:]");

    // one bit difference
    XCTAssertFalse([f containsData:@"19108ad8ed9bb6274d3980bab5a85c048f0950c8".hexToData],
                  @"[BRBloomFilter containsData:]");

    [f insertData:@"b5a2c786d9ef4658287ced5914b37a1b4aa32eee".hexToData];

    XCTAssertTrue([f containsData:@"b5a2c786d9ef4658287ced5914b37a1b4aa32eee".hexToData],
                 @"[BRBloomFilter containsData:]");

    [f insertData:@"b9300670b4c5366e95b2699e8b18bc75e5f729c5".hexToData];

    XCTAssertTrue([f containsData:@"b9300670b4c5366e95b2699e8b18bc75e5f729c5".hexToData],
                 @"[BRBloomFilter containsData:]");

    // check against satoshi client output
    XCTAssertEqualObjects(@"03614e9b050000000000000001".hexToData, f.data, @"[BRBloomFilter data:]");
}

- (void)testBloomFilterWithTweak
{
    BRBloomFilter *f = [[BRBloomFilter alloc] initWithFalsePositiveRate:.01 forElementCount:3 tweak:2147483649
                        flags:BLOOM_UPDATE_P2PUBKEY_ONLY];

    [f insertData:@"99108ad8ed9bb6274d3980bab5a85c048f0950c8".hexToData];
    
    XCTAssertTrue([f containsData:@"99108ad8ed9bb6274d3980bab5a85c048f0950c8".hexToData],
                 @"[BRBloomFilter containsData:]");
    
    // one bit difference
    XCTAssertFalse([f containsData:@"19108ad8ed9bb6274d3980bab5a85c048f0950c8".hexToData],
                  @"[BRBloomFilter containsData:]");
    
    [f insertData:@"b5a2c786d9ef4658287ced5914b37a1b4aa32eee".hexToData];
    
    XCTAssertTrue([f containsData:@"b5a2c786d9ef4658287ced5914b37a1b4aa32eee".hexToData],
                 @"[BRBloomFilter containsData:]");
    
    [f insertData:@"b9300670b4c5366e95b2699e8b18bc75e5f729c5".hexToData];
    
    XCTAssertTrue([f containsData:@"b9300670b4c5366e95b2699e8b18bc75e5f729c5".hexToData],
                 @"[BRBloomFilter containsData:]");

    // check against satoshi client output
    XCTAssertEqualObjects(@"03ce4299050000000100008002".hexToData, f.data, @"[BRBloomFilter data:]");
}

#pragma mark - testMerkleBlock
#ifndef USE_MAZA
- (void)testMerkleBlock
{
    // block 10001 filtered to include only transactions 0, 1, 2, and 6
    NSData *block = @"0100000006e533fd1ada86391f3f6c343204b0d278d4aaec1c0b20aa27ba0300000000006abbb3eb3d733a9fe18967fd7"
                     "d4c117e4ccbbac5bec4d910d900b3ae0793e77f54241b4d4c86041b4089cc9b0c000000084c30b63cfcdc2d35e3329421"
                     "b9805ef0c6565d35381ca857762ea0b3a5a128bbca5065ff9617cbcba45eb23726df6498a9b9cafed4f54cbab9d227b00"
                     "35ddefbbb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181d77706be8b1dcc91112eada86d"
                     "424e2d0a8907c3488b6e44fda5a74a25cbc7d6bb4fa04245f4ac8a1a571d5537eac24adca1454d65eda446055479af6c6"
                     "d4dd3c9ab658448c10b6921b7a4ce3021eb22ed6bb6a7fde1e5bcc4b1db6615c6abc5ca042127bfaf9f44ebce29cb29c6"
                     "df9d05b47f35b2edff4f0064b578ab741fa78276222651209fe1a2c4c0fa1c58510aec8b090dd1eb1f82f9d261b8273b5"
                     "25b02ff1a".hexToData;
    BRMerkleBlock *b = [BRMerkleBlock blockWithMessage:block];
    UInt256 hash;
    
    hash = *(UInt256 *)@"00000000000080b66c911bd5ba14a74260057311eaeb1982802f7010f1a9f090".hexToData.reverse.bytes;
    XCTAssertTrue(uint256_eq(b.blockHash, hash), @"[BRMerkleBlock blockHash]");

    XCTAssertTrue(b.valid, @"[BRMerkleBlock isValid]");

    hash = *(UInt256 *)@"4c30b63cfcdc2d35e3329421b9805ef0c6565d35381ca857762ea0b3a5a128bb".hexToData.bytes;
    XCTAssertTrue([b containsTxHash:hash], @"[BRMerkleBlock containsTxHash:]");

    XCTAssertTrue(b.txHashes.count == 4, @"[BRMerkleBlock txHashes]");

    hash = *(UInt256 *)@"4c30b63cfcdc2d35e3329421b9805ef0c6565d35381ca857762ea0b3a5a128bb".hexToData.bytes;
    XCTAssertEqualObjects(b.txHashes[0], uint256_obj(hash), @"[BRMerkleBlock txHashes]");

    hash = *(UInt256 *)@"ca5065ff9617cbcba45eb23726df6498a9b9cafed4f54cbab9d227b0035ddefb".hexToData.bytes;
    XCTAssertEqualObjects(b.txHashes[1], uint256_obj(hash), @"[BRMerkleBlock txHashes]");

    hash = *(UInt256 *)@"bb15ac1d57d0182aaee61c74743a9c4f785895e563909bafec45c9a2b0ff3181".hexToData.bytes;
    XCTAssertEqualObjects(b.txHashes[2], uint256_obj(hash), @"[BRMerkleBlock txHashes]");

    hash = *(UInt256 *)@"c9ab658448c10b6921b7a4ce3021eb22ed6bb6a7fde1e5bcc4b1db6615c6abc5".hexToData.bytes;
    XCTAssertEqualObjects(b.txHashes[3], uint256_obj(hash), @"[BRMerkleBlock txHashes]");
    
    //TODO: test a block with an odd number of tree rows both at the tx level and merkle node level
    
    //TODO:XXXX test verifyDifficultyFromPreviousBlock
}
#endif
#pragma mark - UIImage+Utils

- (void)testUIImageUtils
{
    
}

#pragma mark - performance

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
