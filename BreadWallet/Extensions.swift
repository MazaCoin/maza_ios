//
//  Extensions.swift
//  BreadWallet
//
//  Created by Samuel Sutch on 1/30/16.
//  Copyright (c) 2016 breadwallet LLC
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

import Foundation

extension Data {

    func SHA256_2() -> UInt256 {
        var sha256 = UInt256()
        // Convert to NSData to more easily use legacy function
        let localdata = self as NSData
        SHA256(&sha256, localdata.bytes, localdata.length);
        let size256 = MemoryLayout.size(ofValue: sha256)
        var oldsha256 = sha256
        SHA256(&sha256, &oldsha256, size256);
        return sha256;
    }
}


extension String {
    
    func md5() -> String {
        let data = (self as NSString).data(using: String.Encoding.utf8.rawValue)!
        let result = NSMutableData(length: Int(128/8))!
        let resultBytes = result.mutableBytes
        MD5(resultBytes, (data as NSData).bytes, data.count)
        
        //        let a = UnsafeBufferPointer<CUnsignedChar>(start: resultBytes, count: result.length)
        let a = resultBytes.assumingMemoryBound(to: CUnsignedChar.self)
        let hash = NSMutableString()
        
        for i in 0..<result.length {
            hash.appendFormat("%02x", a[i])
        }
        
        return hash as String
    }
    
    static func buildQueryString(_ options: [String: [String]]?, includeQ: Bool = false) -> String {
        var s = ""
        if let options = options, options.count > 0 {
            s = includeQ ? "?" : ""
            var i = 0
            for (k, vals) in options {
                for v in vals {
                    if i != 0 {
                        s += "&"
                    }
                    i += 1
                    s += "\(k.urlEscapedString)=\(v.urlEscapedString)"
                }
            }
        }
        return s
    }
}
