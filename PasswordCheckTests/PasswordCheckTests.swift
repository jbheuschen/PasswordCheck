//
//  PasswordCheckTests.swift
//  PasswordCheckTests
//
//  Created by Julian Benedikt Heuschen on 1/27/21.
//

import XCTest
@testable import PasswordCheck

class PasswordCheckTests: XCTestCase {

    override func setUpWithError() throws {
    }

    override func tearDownWithError() throws {
    }

    func testBreached() throws {
        let expectation = self.expectation(description: "123 is breached")
        try! PasswordCheck.check(forPassword: "123").execute {
            XCTAssertFalse($0)
            expectation.fulfill()
        }
        self.waitForExpectations(timeout: 5.0, handler: nil)
    }

}
