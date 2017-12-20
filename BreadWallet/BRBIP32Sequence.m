//
//  BRBIP32Sequence.m
//  BreadWallet
//
//  Created by Aaron Voisine on 7/19/13.
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

#import "BRBIP32Sequence.h"
#import "BRKey.h"
#import "NSString+Bitcoin.h"
#import "NSData+Bitcoin.h"
#import "NSMutableData+Bitcoin.h"

#define BIP32_SEED_KEY "Bitcoin seed"

#ifdef USE_MAZA
#ifdef MAZA_TESTNET
#define BIP32_XPRV     "\x04\x35\x83\x94" //// BIP32 prvkeys start with 'tpub'
#define BIP32_XPUB     "\x04\x35\x87\xcf" //// BIP32 pubkeys start with 'tprv'
#else
#define BIP32_XPRV     "\x04\x88\xb2\x1e" //
#define BIP32_XPUB     "\x04\x88\xad\xe4" //
#endif
#else
#define BIP32_XPRV     "\x04\x88\xAD\xE4"
#define BIP32_XPUB     "\x04\x88\xB2\x1E"
#endif

#define BIP32_BTC_PRV     "\x04\x88\xAD\xE4"
#define BIP32_BTC_PUB     "\x04\x88\xB2\x1E"


// BIP32 is a scheme for deriving chains of addresses from a seed value
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

// Private parent key -> private child key
//
// CKDpriv((kpar, cpar), i) -> (ki, ci) computes a child extended private key from the parent extended private key:
//
// - Check whether i >= 2^31 (whether the child is a hardened key).
//     - If so (hardened child): let I = HMAC-SHA512(Key = cpar, Data = 0x00 || ser256(kpar) || ser32(i)).
//       (Note: The 0x00 pads the private key to make it 33 bytes long.)
//     - If not (normal child): let I = HMAC-SHA512(Key = cpar, Data = serP(point(kpar)) || ser32(i)).
// - Split I into two 32-byte sequences, IL and IR.
// - The returned child key ki is parse256(IL) + kpar (mod n).
// - The returned chain code ci is IR.
// - In case parse256(IL) >= n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i
//   (Note: this has probability lower than 1 in 2^127.)
//
static void CKDpriv(UInt256 *k, UInt256 *c, uint32_t i)
{
    uint8_t buf[sizeof(BRPubKey) + sizeof(i)];
    UInt512 I;
    
    if (i & BIP32_HARD) {
        buf[0] = 0;
        *(UInt256 *)&buf[1] = *k;
    }
    else secp256k1_point_mul(buf, NULL, *k, 1);

    *(uint32_t *)&buf[sizeof(BRPubKey)] = CFSwapInt32HostToBig(i);

    HMAC(&I, SHA512, sizeof(UInt512), c, sizeof(*c), buf, sizeof(buf)); // I = HMAC-SHA512(c, k|P(k) || i)
    
    *k = secp256k1_mod_add(*(UInt256 *)&I, *k); // k = IL + k (mod n)
    *c = *(UInt256 *)&I.u8[sizeof(UInt256)]; // c = IR
    
    memset(buf, 0, sizeof(buf));
    memset(&I, 0, sizeof(I));
}


// helper function for serializing BIP32 master public/private keys to standard export format
static NSString *serialize(uint8_t depth, uint32_t fingerprint, uint32_t child, UInt256 chain, NSData *key)
{
    NSMutableData *d = [NSMutableData secureDataWithCapacity:14 + key.length + sizeof(chain)];
    
    fingerprint = CFSwapInt32HostToBig(fingerprint);
    child = CFSwapInt32HostToBig(child);
    
    [d appendBytes:key.length < 33 ? BIP32_BTC_PRV : BIP32_BTC_PUB length:4];
    [d appendBytes:&depth length:1];
    [d appendBytes:&fingerprint length:sizeof(fingerprint)];
    [d appendBytes:&child length:sizeof(child)];
    [d appendBytes:&chain length:sizeof(chain)];
    if (key.length < 33) [d appendBytes:"\0" length:1];
    [d appendData:key];
    
    return [NSString base58checkWithData:d];
}


@implementation BRBIP32Sequence

#pragma mark - BRKeySequence

// master public key format is:  32 byte key || 32 byte chain code
- (NSData *)masterPublicKeyFromSeed:(NSData *)seed
{
    if (! seed) return nil;
#ifdef USE_MAZA
    NSData *mpk = [self getDerivedKeychainFromSeed:seed WithPath:@"m/44'/13'/0'"];
#else
    NSData *mpk = [self getDerivedKeychainFromSeed:seed WithPath:@"m/44'/0'/0'"];
#endif
    return mpk;
}

- (NSData *)publicKey:(uint32_t)n internal:(BOOL)internal masterPublicKey:(NSData *)masterPublicKey
{
    int first = (internal) ? 1 : 0;
    
    // Get back to starting position with masterPublicKey
    NSData *key_data = [masterPublicKey subdataWithRange:NSMakeRange(0,32)];
    NSData *ch_data = [masterPublicKey subdataWithRange:NSMakeRange(32,32)];
    
    NSData *mpk0 = [self NextKeyFrom:key_data Chaincode:ch_data Index:(uint32_t)first Hard:NO];
    key_data = [mpk0 subdataWithRange:NSMakeRange(0,32)];
    ch_data = [mpk0 subdataWithRange:NSMakeRange(32,32)];

    NSData *key_plus_ch = [self NextKeyFrom:key_data Chaincode:ch_data Index:(uint32_t)n Hard:NO];
 
    NSData *key = [key_plus_ch subdataWithRange:NSMakeRange(0,32)];
    UInt256 secret = *(UInt256 *)key.bytes;
    BRKey *k = [BRKey keyWithSecret:secret compressed:YES];
    NSMutableData *data = [NSMutableData data];
    [data appendData:k.publicKey];

    return data;
}

- (NSArray *)privateKeys:(NSArray *)n internal:(BOOL)internal fromSeed:(NSData *)seed
{
    if (! seed || ! n) return nil;
    if (n.count == 0) return @[];
    
    NSMutableArray *a = [NSMutableArray arrayWithCapacity:n.count];
    NSData *mpk = [self masterPublicKeyFromSeed:seed];
    NSData *key_data = [mpk subdataWithRange:NSMakeRange(0,32)];
    NSData *ch_data = [mpk subdataWithRange:NSMakeRange(32,32)];

    uint8_t version = MAZA_PRIVKEY;
    
#if MAZA_TESTNET
    version = MAZA_PRIVKEY_TEST;
#endif
    
    int first = (internal) ? 1 : 0;
    NSData *mpk0 = [self NextKeyFrom:key_data Chaincode:ch_data Index:(uint32_t)first Hard:NO];
    key_data = [mpk0 subdataWithRange:NSMakeRange(0,32)];
    ch_data = [mpk0 subdataWithRange:NSMakeRange(32,32)];
    

    for (NSNumber *i in n) {
        NSMutableData *privKey = [NSMutableData secureDataWithCapacity:34];
        NSData *key_plus_ch = [self NextKeyFrom:key_data Chaincode:ch_data Index:i.unsignedIntValue Hard:NO];
        NSData *key = [key_plus_ch subdataWithRange:NSMakeRange(0,32)];
        
        //NSLog(@"⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️ secret key for index %d ....= %@",i.unsignedIntValue, key);
        
        [privKey appendBytes:&version length:1];
        [privKey appendData:key];
        [privKey appendBytes:"\x01" length:1]; // specifies compressed pubkey format
        [a addObject:[NSString base58checkWithData:privKey]];
    }
    
    return a;
}


- (NSString *)privateKey:(uint32_t)n internal:(BOOL)internal fromSeed:(NSData *)seed
{
    return seed ? [self privateKeys:@[@(n)] internal:internal fromSeed:seed].lastObject : nil;
}


#pragma mark - authentication key

- (NSString *)authPrivateKeyFromSeed:(NSData *)seed
{
    if (! seed) return nil;
    
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);
    
    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
    uint8_t version = MAZA_PRIVKEY;
    
#if MAZA_TESTNET
    version = MAZA_PRIVKEY_TEST;
#endif
    
    // path m/1H/0 (same as copay uses for bitauth)
    CKDpriv(&secret, &chain, 1 | BIP32_HARD);
    CKDpriv(&secret, &chain, 0);
    
    NSMutableData *privKey = [NSMutableData secureDataWithCapacity:34];

    [privKey appendBytes:&version length:1];
    [privKey appendBytes:&secret length:sizeof(secret)];
    [privKey appendBytes:"\x01" length:1]; // specifies compressed pubkey format
    return [NSString base58checkWithData:privKey];
}

- (NSData *)getSecretFromSeed:(NSData *)seed
{
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);
    
    UInt256 secret = *(UInt256 *)&I;
    NSData *new_sec = [NSData dataWithBytes:&secret length:sizeof(secret)];
    return new_sec;
}



- (NSData *)call_sep:(NSData *)secret chain:(NSData *)chain {
    UInt256 s;
    UInt256 c = *(UInt256 *)secret.bytes;
    UInt256 k = *(UInt256 *)chain.bytes;
    
    s = secp256k1_mod_add(c, k); // k = IL + k (mod n)
    NSData *digest = [NSData dataWithBytes:&s length:sizeof(s)];
    
    return digest;
}



-(NSData *)NextKeyFrom:(NSData *)privatekey Chaincode:(NSData *)chaincode Index:(uint32_t)index Hard:(BOOL)hardened
{
    NSMutableData *data = [NSMutableData data];
    if (hardened) {
        uint8_t padding = 0;
        [data appendBytes:&padding length:1];
        [data appendData:privatekey];
    } else {
        UInt256 secret = *(UInt256 *)privatekey.bytes;
        BRKey *k = [BRKey keyWithSecret:secret compressed:YES];
        [data appendData:k.publicKey];
    }
    
    uint32_t indexBE = OSSwapHostToBigInt32(hardened ? (0x80000000 | index) : index);
    [data appendBytes:&indexBE length:sizeof(indexBE)];
    
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), chaincode.bytes, chaincode.length, data.bytes, data.length);
    
    UInt256 secret = *(UInt256 *)&I;
    NSData * sec = [NSData dataWithBytes:&secret length:sizeof(secret)];
    
    //NSLog(@" secret out for index %d = %@",index,sec);
    
    // NSLog(@" For call_sep %@ : %@",sec,private_key);
    //NSData *new_point = [self call_sep:sec chain:privatekey];
    UInt256 c = *(UInt256 *)sec.bytes;
    UInt256 k = *(UInt256 *)privatekey.bytes;
    UInt256 s;
    
    s = secp256k1_mod_add(c, k); // k = IL + k (mod n)
    
    UInt256 new_chaincode = *(UInt256 *)&I.u8[sizeof(UInt256)];
    NSData *new_sec = [NSData dataWithBytes:&s length:sizeof(s)];
    NSData *new_chain = [NSData dataWithBytes:&new_chaincode length:sizeof(new_chaincode)];
    
    NSMutableData *mpk = [NSMutableData secureData];
    [mpk appendData:new_sec];
    [mpk appendData:new_chain];
    return mpk;
    
}

// Parses the BIP32 path and derives the chain of keychains accordingly.
// Path syntax: (m?/)?([0-9]+'?(/[0-9]+'?)*)?
// The following paths are valid:
//
// "" (root key)
// "m" (root key)
// "/" (root key)
// "m/0'" (hardened child #0 of the root key)
// "/0'" (hardened child #0 of the root key)
// "0'" (hardened child #0 of the root key)
// "m/44'/1'/2'" (BIP44 testnet account #2)
// "/44'/1'/2'" (BIP44 testnet account #2)
// "44'/1'/2'" (BIP44 testnet account #2)
//
// The following paths are invalid:
//
// "m / 0 / 1" (contains spaces)
// "m/b/c" (alphabetical characters instead of numerical indexes)
// "m/1.2^3" (contains illegal characters)

- (NSData *) getDerivedKeychainFromSeed:(NSData *)seed WithPath:(NSString*)path {
    
    if (! seed) return nil;
    
    if (path == nil) return nil;
    
    if ([path isEqualToString:@"m"] ||
        [path isEqualToString:@"/"] ||
        [path isEqualToString:@""]) {
        return nil;
    }
    
    UInt512 I;
        
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);
    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
        
    NSData * key_data = [NSData dataWithBytes:&secret length:sizeof(secret)];
    NSData * ch_data = [NSData dataWithBytes:&chain length:sizeof(chain)];
    //NSLog(@" Root secret = %@",key_data);
    
    if ([path rangeOfString:@"m/"].location == 0) { // strip "m/" from the beginning.
        path = [path substringFromIndex:2];
    }
    for (NSString* chunk in [path componentsSeparatedByString:@"/"]) {
        if (chunk.length == 0) {
            continue;
        }
        BOOL hardened = NO;
        NSString* indexString = chunk;
        if ([chunk rangeOfString:@"'"].location == chunk.length - 1) {
            hardened = YES;
            indexString = [chunk substringToIndex:chunk.length - 1];
        }
        
        // Make sure the chunk is just a number
        NSInteger i = [indexString integerValue];
        if (i >= 0 && [@(i).stringValue isEqualToString:indexString]) {
            NSData *new_data = [self NextKeyFrom:key_data Chaincode:ch_data Index:(uint32_t)i Hard:hardened];
            // Get back to starting position with masterPublicKey
            key_data = [new_data subdataWithRange:NSMakeRange(0,32)];
            ch_data = [new_data subdataWithRange:NSMakeRange(32,32)];
        } else {
            return nil;
        }
    }
    NSMutableData *mpk = [NSMutableData secureData];
    [mpk appendData:key_data];
    [mpk appendData:ch_data];
    return mpk;

}

- (NSString *)serializedPrivateMasterFromSeed:(NSData *)seed
{
    if (! seed) return nil;
    
    UInt512 I;
    
    HMAC(&I, SHA512, sizeof(UInt512), BIP32_SEED_KEY, strlen(BIP32_SEED_KEY), seed.bytes, seed.length);
    
    UInt256 secret = *(UInt256 *)&I, chain = *(UInt256 *)&I.u8[sizeof(UInt256)];
    
    return serialize(0, 0, 0, chain, [NSData dataWithBytes:&secret length:sizeof(secret)]);
}


@end
