
//
//  BRAPIClient.swift
//  BreadWallet
//
//  Created by Samuel Sutch on 11/4/15.
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

let BRAPIClientErrorDomain = "BRApiClientErrorDomain"

// these flags map to api feature flag name values
// eg "buy-maza-with-cash" is a persistent name in the /me/features list
@objc public enum BRFeatureFlags: Int, CustomStringConvertible {
    case buyMaza
    case earlyAccess
    
    public var description: String {
        switch self {
        case .buyMaza: return "buy-maza";
        case .earlyAccess: return "early-access";
        }
    }
}

public typealias URLSessionTaskHandler = (Data?, HTTPURLResponse?, NSError?) -> Void
public typealias URLSessionChallengeHandler = (URLSession.AuthChallengeDisposition, URLCredential?) -> Void

extension String {
    static var urlQuoteCharacterSet: CharacterSet {
        let cset = (NSMutableCharacterSet.urlQueryAllowed as NSCharacterSet).mutableCopy() as! NSMutableCharacterSet
        cset.removeCharacters(in: "?=&")
        return cset as CharacterSet
    }
    
    var urlEscapedString: String {
        return self.addingPercentEncoding(
            withAllowedCharacters: String.urlQuoteCharacterSet)!
    }
}


func getHeaderValue(_ k: String, d: [String: String]?) -> String? {
    guard let d = d else {
        return nil
    }
    if let v = d[k] { // short path: attempt to get the header directly
        return v
    }
    let lkKey = k.lowercased() // long path: compare lowercase keys
    for (lk, lv) in d {
        if lk.lowercased() == lkKey {
            return lv
        }
    }
    return nil
}

func getAuthKey() -> BRKey? {
    if let manager = BRWalletManager.sharedInstance(), let authKey = manager.authPrivateKey {
        return BRKey(privateKey: authKey)
    }
    return nil
}

func getDeviceId() -> String {
    let ud = UserDefaults.standard
    if let s = ud.string(forKey: "BR_DEVICE_ID") {
        return s
    }
    let s = CFUUIDCreateString(nil, CFUUIDCreate(nil)) as String
    ud.setValue(s, forKey: "BR_DEVICE_ID")
    print("new device id \(s)")
    return s
}


func isBreadChallenge(_ r: HTTPURLResponse) -> Bool {
    if let headers = r.allHeaderFields as? [String: String],
        let challenge = getHeaderValue("www-authenticate", d: headers) {
        if challenge.lowercased().hasPrefix("bread") {
            return true
        }
    }
    return false
}

func buildURLResourceString(_ url: URL?) -> String {
    var urlStr = ""
    if let url = url {
        urlStr = "\(url.path)"
        if let query = url.query {
            if query.lengthOfBytes(using: String.Encoding.utf8) > 0 {
                urlStr = "\(urlStr)?\(query)"
            }
        }
    }
    return urlStr
}



func buildRequestSigningString(_ r: URLRequest) -> String {
    var parts = [
        r.httpMethod ?? "",
        "",
        getHeaderValue("content-type", d: r.allHTTPHeaderFields) ?? "",
        getHeaderValue("date", d: r.allHTTPHeaderFields) ?? "",
        buildURLResourceString(r.url)
    ]
    if let meth = r.httpMethod {
        switch meth {
        case "POST", "PUT", "PATCH":
            if let d = r.httpBody , d.count > 0 {
                let sha = (d as NSData).sha256()
                parts[1] = (NSData(uInt256: sha) as NSData).base58String()
            }
        default: break
        }
    }
    return parts.joined(separator: "\n")
}

var rfc1123DateFormatter: DateFormatter {
    let fmt = DateFormatter()
    fmt.timeZone = TimeZone(abbreviation: "GMT")
    fmt.dateFormat = "EEE',' dd MMM yyyy HH':'mm':'ss 'GMT'";
    fmt.locale = Locale(identifier: "en_US")
    return fmt
}

func httpDateNow() -> String {
    return rfc1123DateFormatter.string(from: Date())
}

@objc open class BRAPIClient: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    var logEnabled = true
    var proto = "https"
    var host = "api.breadwallet.com"
    
    // isFetchingAuth is set to true when a request is currently trying to renew authentication (the token)
    // it is useful because fetching auth is not idempotent and not reentrant, so at most one auth attempt
    // can take place at any one time
    fileprivate var isFetchingAuth = false
    
 
    
    // used when requests are waiting for authentication to be fetched
    fileprivate var authFetchGroup: DispatchGroup = DispatchGroup()
    
    
    // the NSURLSession on which all NSURLSessionTasks are executed
    fileprivate var session: Foundation.URLSession {
        if _session == nil {
            let config = URLSessionConfiguration.default
            _session = Foundation.URLSession(configuration: config, delegate: self, delegateQueue: queue)
        }
        return _session!
    }
    
    // the queue on which the NSURLSession operates
    fileprivate var queue = OperationQueue()

    fileprivate var _session: Foundation.URLSession? = nil
    
    var baseUrl: String {
        return "\(proto)://\(host)"
    }
    
    var userAccountKey: String {
        return baseUrl
    }
    
    fileprivate var _serverPubKey: BRKey? = nil
    var serverPubKey: BRKey {
        if _serverPubKey == nil {
            let encoded = "24jsCR3itNGbbmYbZnG6jW8gjguhqybCXsoUAgfqdjprz"
            _serverPubKey = BRKey(publicKey: NSData(base58String: encoded) as Data)!
        }
        return _serverPubKey!
    }
    
    // the singleton
    static let sharedClient = BRAPIClient()
    
    
    func log(_ format: String, args: CVarArg...) -> Int? {
        if !logEnabled {
            return 1
        }
        let s = String(format: format, arguments: args)
        print("[BRAPIClient] \(s)")
        return 2
    }
    
    // MARK: Networking functions
    
    // Constructs a full NSURL for a given path and url parameters
    func url(_ path: String, args: Dictionary<String, String>? =  nil) -> URL {
        func joinPath(_ k: String...) -> URL {
            return URL(string: ([baseUrl] + k).joined(separator: ""))!
        }
        
        if let args = args {
            return joinPath(path + "?" + args.map({ (elem) -> String in
                return "\(elem.0.urlEscapedString)=\(elem.1.urlEscapedString)"
            }).joined(separator: "&"))
        } else {
            return joinPath(path)
        }
    }
    
    func signRequest(request: NSURLRequest) -> NSURLRequest {
        let mutableRequest = request.mutableCopy() as! NSMutableURLRequest
        let dateHeader = getHeaderValue("date", d: mutableRequest.allHTTPHeaderFields ?? Dictionary<String, String>())
        if dateHeader == nil {
            // add Date header if necessary
            mutableRequest.setValue(httpDateNow(), forHTTPHeaderField: "Date")
        }
        do {
            if let tokenData = try BRKeychain.loadDataForUserAccount(userAccountKey),
                let token = tokenData["token"], let authKey = getAuthKey() {
                let data = buildRequestSigningString(mutableRequest as URLRequest).data(using: String.Encoding.utf8)
                let sha = data?.SHA256_2()
                let sig1 = authKey.compactSign(sha!)
                let sig = [NSString .base58(with: sig1)]
                mutableRequest.setValue("bread \(token):\(String(describing: sig))", forHTTPHeaderField: "Authorization")
            }
        } catch let e as BRKeychainError {
            _ = log("keychain error fetching tokoen \(e)")
        } catch let e {
            _ = log("unexpected error fetching keychain data \(e)")
        }
        return mutableRequest.copy() as! NSURLRequest
    }
    
    func dataTaskWithRequest(request: NSURLRequest, authenticated: Bool = false,
                             retryCount: Int = 0, handler: @escaping URLSessionTaskHandler) -> URLSessionDataTask {
        let start = NSDate()
        var logLine = ""
        if let meth = request.httpMethod, let u = request.url {
            logLine = "\(meth) \(u) auth=\(authenticated) retry=\(retryCount)"
        }
        let origRequest = request.mutableCopy() as! NSURLRequest
        var actualRequest = request
        if authenticated && getAuthKey() != nil {
            actualRequest = signRequest(request: request)
        }
        return session.dataTask(with: actualRequest as URLRequest) { (data, resp, err) -> Void in
            let end = NSDate()
            let dur = Int(end.timeIntervalSince(start as Date) * 1000)
            if let httpResp = resp as? HTTPURLResponse {
                var errStr = ""
                if httpResp.statusCode >= 400 {
                    if let data = data, let s = NSString(data: data, encoding: String.Encoding.utf8.rawValue) {
                        errStr = s as String
                    }
                }
                
                _ = self.log("\(logLine) -> status=\(httpResp.statusCode) duration=\(dur)ms errStr=\(errStr)")
                
                if authenticated && isBreadChallenge(httpResp) {
                    _ = self.log("got authentication challenge from API - will attempt to get token")
                    self.getToken({ (err) -> Void in
                        if err != nil && retryCount < 1 { // retry once
                            _ = self.log("error retrieving token: \(String(describing: err)) - will retry")
                            
                            DispatchQueue.main.asyncAfter(deadline: DispatchTime(uptimeNanoseconds: 1)) {
                                self.dataTaskWithRequest(
                                    request: origRequest, authenticated: authenticated,
                                    retryCount: retryCount + 1, handler: handler
                                    ).resume()
                            }
                            
                            } else if err != nil && retryCount > 0 { // fail if we already retried
                            _ = self.log("error retrieving token: \(String(describing: err)) - will no longer retry")
                            handler(nil, nil, err)
                        } else if retryCount < 1 { // no error, so attempt the request again
                            _ = self.log("retrieved token, so retrying the original request")
                            self.dataTaskWithRequest(
                                request: origRequest, authenticated: authenticated,
                                retryCount: retryCount + 1, handler: handler).resume()
                        } else {
                            _ = self.log("retried token multiple times, will not retry again")
                            handler(data, httpResp, err)
                        }
                    })
                } else {
                    handler(data, httpResp, err as NSError?)
                }
            } else {
                _ = self.log("\(logLine) encountered connection error \(String(describing: err))")
                handler(data, nil, err! as NSError)
            }
        }
    }
    
    // retrieve a token and save it in the keychain data for this account
    func getToken(_ handler: @escaping (NSError?) -> Void) {
        if isFetchingAuth {
            _ = log("already fetching auth, waiting...")
            authFetchGroup.notify(queue: DispatchQueue.main) {
                handler(nil)
            }
            return
        }
        guard let authKey = getAuthKey(), let authPubKey = authKey.publicKey else {
            return handler(NSError(domain: BRAPIClientErrorDomain, code: 500, userInfo: [
                NSLocalizedDescriptionKey: NSLocalizedString("Wallet not ready", comment: "")]))
        }
        isFetchingAuth = true
        _ = log("auth: entering group")
        authFetchGroup.enter()
        var req = URLRequest(url: url("/token"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let reqJson = [
            "pubKey": (authPubKey as NSData).base58String(),
            "deviceID": getDeviceId()
        ]
        do {
            let dat = try JSONSerialization.data(withJSONObject: reqJson, options: [])
            req.httpBody = dat
        } catch let e {
            _ = log("JSON Serialization error \(e)")
            isFetchingAuth = false
            authFetchGroup.leave()
            return handler(NSError(domain: BRAPIClientErrorDomain, code: 500, userInfo: [
                NSLocalizedDescriptionKey: NSLocalizedString("JSON Serialization Error", comment: "")]))
        }
        session.dataTask(with: req, completionHandler: { (data, resp, err) in
            DispatchQueue.main.async {
                if let httpResp = resp as? HTTPURLResponse {
                    // unsuccessful response from the server
                    if httpResp.statusCode != 200 {
                        if let data = data, let s = String(data: data, encoding: String.Encoding.utf8) {
                            _ = self.log("Token error: \(s)")
                        }
                        self.isFetchingAuth = false
                        self.authFetchGroup.leave()
                        return handler(NSError(domain: BRAPIClientErrorDomain, code: httpResp.statusCode, userInfo: [
                            NSLocalizedDescriptionKey: NSLocalizedString("Unable to retrieve API token", comment: "")]))
                    }
                }
                if let data = data {
                    do {
                        let json = try JSONSerialization.jsonObject(with: data, options: .allowFragments)
                        _ = self.log("POST /token json response: \(json)")
                        if let topObj = json as? NSDictionary,
                            let _ = topObj["token"] as? NSString,
                            let _ = topObj["userID"] as? NSString,
                            let _ = BRWalletManager.sharedInstance() {
                            // success! store it in the keychain
                            // let kcData = ["token": tok, "userID": uid]
                            /////walletManager.userAccount = kcData
                        }
                    } catch let e {
                        _ = self.log("JSON Deserialization error \(e)")
                    }
                }
                self.isFetchingAuth = false
                self.authFetchGroup.leave()
                handler(err as NSError?)
            }
        }) .resume()
    }

    
    // MARK: URLSession Delegate
    
    public func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        _ = log("URLSession didBecomeInvalidWithError: \(String(describing: error))")
    }
    
    private func urlSession(_ session: URLSession, task: URLSessionTask,
                           didReceive didReceiveChallenge: URLAuthenticationChallenge,
                           completionHandler: URLSessionChallengeHandler) {
            _ = log("URLSession task \(task) didReceivechallenge \(didReceiveChallenge.protectionSpace)")
            
    }
    
    func urlSession(_ session: URLSession, didReceive didReceiveChallenge: URLAuthenticationChallenge,
                           completionHandler: URLSessionChallengeHandler) {
        _ = log("URLSession didReceiveChallenge \(didReceiveChallenge) \(didReceiveChallenge.protectionSpace)")
        // handle HTTPS authentication
        if didReceiveChallenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if (didReceiveChallenge.protectionSpace.host == host
                && didReceiveChallenge.protectionSpace.serverTrust != nil) {
                _ = log("URLSession challenge accepted!")
                completionHandler(.useCredential,
                    URLCredential(trust: didReceiveChallenge.protectionSpace.serverTrust!))
            } else {
                _ = log("URLSession challenge rejected")
                completionHandler(.rejectProtectionSpace, nil)
            }
        }
    }
    
    // MARK: API Functions
    
    // Fetches the /v1/fee-per-kb endpoint
    public func feePerKb(_ handler: @escaping (_ feePerKb: uint_fast64_t, _ error: String?) -> Void) {
        let req = URLRequest(url: url("/v1/fee-per-kb"))
        let task = self.dataTaskWithRequest(request: req as NSURLRequest) { (data, response, err) -> Void in
            var feePerKb: uint_fast64_t = 0
            var errStr: String? = nil
            if err == nil {
                do {
                    let parsedObject: Any? = try JSONSerialization.jsonObject(
                        with: data!, options: JSONSerialization.ReadingOptions.allowFragments)
                    if let top = parsedObject as? NSDictionary, let n = top["fee_per_kb"] as? NSNumber {
                        feePerKb = n.uint64Value
                    }
                } catch (let e) {
                    _ = self.log("fee-per-kb: error parsing json \(e)")
                }
                if feePerKb == 0 {
                    errStr = "invalid json"
                }
            } else {
                _ = self.log("fee-per-kb network error: \(String(describing: err))")
                errStr = "bad network connection"
            }
            handler(feePerKb, errStr)
        }
        task.resume()
    }
    
    // MARK: feature flags API
    
    open func defaultsKeyForFeatureFlag(_ name: String) -> String {
        return "ff:\(name)"
    }
    
    open func updateFeatureFlags() {
        let req = URLRequest(url: url("/me/features"))
        dataTaskWithRequest(request: req as NSURLRequest, authenticated: true) { (data, resp, err) in
            if let resp = resp, let data = data {
                if resp.statusCode == 200 {
                    let defaults = UserDefaults.standard
                    do {
                        let j = try JSONSerialization.jsonObject(with: data, options: [])
                        let features = j as! [[String: AnyObject]]
                        for feat in features {
                            if let fn = feat["name"], let fname = fn as? String, let fe = feat["enabled"], let fenabled = fe as? Bool {
                                _ = self.log("feature \(fname) enabled: \(fenabled)")
                                defaults.set(fenabled, forKey: self.defaultsKeyForFeatureFlag(fname))
                            } else {
                                _ = self.log("malformed feature: \(feat)")
                            }
                        }
                    } catch let e {
                        _ = self.log("error loading features json: \(e)")
                    }
                }
            } else {
                _ = self.log("error fetching features: \(String(describing: err))")
            }
        }.resume()
    }
    
    open func featureEnabled(_ flag: BRFeatureFlags) -> Bool {
        let defaults = UserDefaults.standard
        return defaults.bool(forKey: defaultsKeyForFeatureFlag(flag.description))
    }
    
    // MARK: Assets API
    
    open class func bundleURL(_ bundleName: String) -> URL {
        let fm = FileManager.default
        let docsUrl = fm.urls(for: .documentDirectory, in: .userDomainMask).first!
        let bundleDirUrl = docsUrl.appendingPathComponent("bundles", isDirectory: true)
        let bundleUrl = bundleDirUrl.appendingPathComponent("\(bundleName)-extracted", isDirectory: true)
        return bundleUrl
    }
    
    // Don't use this!
    open func updateBundle(_ bundleName: String, handler: @escaping (_ error: String?) -> Void) { }
}


