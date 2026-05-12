import XCTest

@testable import NFCPassportReader

final class NativeCryptoTests: XCTestCase {
    func testAESCMACMatchesRFC4493EmptyMessageVector() {
        let key = hexRepToBin("2b7e151628aed2a6abf7158809cf4f3c")
        let mac = aesMAC(key: key, msg: [])

        XCTAssertEqual(binToHexRep(mac), "BB1D6929E95937287FA37D129B756746")
    }

    func testAESCMACMatchesRFC4493SingleBlockVector() {
        let key = hexRepToBin("2b7e151628aed2a6abf7158809cf4f3c")
        let message = hexRepToBin("6bc1bee22e409f96e93d7e117393172a")
        let mac = aesMAC(key: key, msg: message)

        XCTAssertEqual(binToHexRep(mac), "070A16B46B4D4144F79BDD9DD04A287C")
    }

    func testAESCMACMatchesRFC4493PartialFinalBlockVector() {
        let key = hexRepToBin("2b7e151628aed2a6abf7158809cf4f3c")
        let message = hexRepToBin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")
        let mac = aesMAC(key: key, msg: message)

        XCTAssertEqual(binToHexRep(mac), "DFA66747DE9AE63030CA32611497C827")
    }

    func testAESCMACMatchesRFC4493FourBlockVector() {
        let key = hexRepToBin("2b7e151628aed2a6abf7158809cf4f3c")
        let message = hexRepToBin(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        let mac = aesMAC(key: key, msg: message)

        XCTAssertEqual(binToHexRep(mac), "51F0BEBF7E3B9D92FC49741779363CFE")
    }

    func testOIDEncodingUsesSwiftASN1() {
        XCTAssertEqual(oidToBytes(oid: "0.4.0.127.0.7.2.2.4.2.2", replaceTag: false),
                       hexRepToBin("060A04007F00070202040202"))
        XCTAssertEqual(oidToBytes(oid: "0.4.0.127.0.7.2.2.4.2.2", replaceTag: true),
                       hexRepToBin("800A04007F00070202040202"))
    }

    func testSwiftASN1DumpKeepsOpenSSLCompatibleHashLabels() throws {
        let digestInfo = hexRepToBin("300D06096086480165030402010500")
        let dump = try ASN1DERParser.dump(data: Data(digestInfo))

        XCTAssertTrue(dump.contains("OBJECT:sha256"))
    }
}
