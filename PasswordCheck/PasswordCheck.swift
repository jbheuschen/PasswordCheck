//
//  PasswordCheck.swift
//  PasswordCheck
//
//  Created by Julian Benedikt Heuschen on 1/27/21.
//

import Foundation
import CryptoKit
import CommonCrypto

public protocol Checker {
    
    func execute(_ result: @escaping (Bool) -> Void) throws
    
}

internal extension Checker {
    
    func doRequest(to: URL, then: @escaping (Data?, URLResponse?, Error?) -> ()) {
        let task = URLSession.shared.dataTask(with: URLRequest(url: to)) { (d, r, e) in
            then(d, r, e)
        }
        task.resume()
    }
    
}

public struct PasswordChecker : Checker {
    
    private static let API = "https://api.pwnedpasswords.com/range/"
    
    private var hash: String
    
    internal init(hash: String) {
        precondition(hash.count == 40) //SHA-1 = 160B
        self.hash = hash
    }
    
    public func execute(_ result: @escaping (Bool) -> Void) throws {
        self.doRequest(to: URL(string: Self.API + self.hash.prefix(5))!) { d, _, e in
            if let d = d {
                if let str = String(data: d, encoding: .utf8) {
                    let res = str.split(whereSeparator: \.isNewline)
                    result(!res.map { String($0.split(separator: ":")[0]).uppercased() }.contains(String(self.hash.uppercased().suffix(35))))
                }
            } else if let e = e {
                NSLog(e.localizedDescription)
            }
        }
    }
    
}

public struct EMailChecker : Checker {
    
    private var email: String
    private var key: String
    
    internal init(email: String, key: String) {
        self.email = email
        self.key = key
    }
    
    public func execute(_ result: @escaping (Bool) -> Void) throws {
        
    }
    
}

public class PasswordCheck {
    
    public static func check(forPassword password: String) -> Checker {
        Self.check(forHash: password.sha1())
    }
    
    public static func check(forHash hash: String) -> Checker {
        PasswordChecker(hash: hash)
    }
    
    public static func check(forEmail email: String, usingKey key: String) -> Checker {
        EMailChecker(email: email, key: key)
    }
    
}

@available(iOS 13.0, macOS 10.15, *)
internal extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }

    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}

internal extension String {
    func sha1() -> String {
        if #available(iOS 13.0, macOS 10.15, *) {
            return Insecure.SHA1.hash(data: self.data(using: .utf8)!).hexStr
        } else {
            let data = Data(self.utf8)
            var digest = [UInt8](repeating: 0, count:Int(CC_SHA1_DIGEST_LENGTH))
            data.withUnsafeBytes {
                _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
            }
            return digest.hexStr
        }
    }
}
