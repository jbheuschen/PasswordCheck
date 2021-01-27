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

public struct PasswordChecker : Checker {
    
    private var hash: String
    
    internal init(hash: String) {
        precondition(hash.count > 5)
        self.hash = String(hash.prefix(5))
    }
    
    public func execute(_ result: @escaping (Bool) -> Void) throws {
        
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

internal extension String {
    func sha1() -> String {
        let data = Data(self.utf8)
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
        }
        let hexBytes = digest.map { String(format: "%02hhx", $0) }
        return hexBytes.joined()
    }
}
