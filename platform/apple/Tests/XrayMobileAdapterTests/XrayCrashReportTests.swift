import XCTest
@testable import XrayMobileAdapter

final class XrayCrashReportTests: XCTestCase {
    func testCurrentLibraryAdvertisesCrashReports() {
        XCTAssertGreaterThanOrEqual(XrayCore.ffiInfo.version.minor, 20)
        XCTAssertTrue(XrayCore.ffiInfo.supports(.crashReports))
    }

    func testTakeReturnsTheCurrentProcessAndClears() throws {
        let report = try XrayCore.takeCrashReports()
        XCTAssertEqual(report.schemaVersion, 1)
        XCTAssertEqual(report.pid, UInt32(ProcessInfo.processInfo.processIdentifier))
        XCTAssertGreaterThan(report.startedUnixMs, 0)
        XCTAssertNoThrow(try XrayCore.takeCrashReports())
    }

    func testDirectoryHoldsAReportTheAppCanRead() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("xray-crash-report-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer {
            try? XrayCore.setCrashReportDirectory(nil)
            try? FileManager.default.removeItem(at: directory)
        }
        let leftBehind = Data(#"{"schemaVersion":1,"pid":7,"startedUnixMs":1,"droppedEvents":0,"events":[]}"#.utf8)
        try leftBehind.write(to: XrayCore.crashReportFileURL(in: directory))

        try XrayCore.setCrashReportDirectory(directory)

        let previous = try XrayCore.readCrashReport(
            at: XrayCore.crashReportFileURL(in: directory, previous: true)
        )
        XCTAssertEqual(previous.pid, 7)
        let current = try XrayCore.readCrashReport(at: XrayCore.crashReportFileURL(in: directory))
        XCTAssertEqual(current.pid, UInt32(ProcessInfo.processInfo.processIdentifier))
    }

    func testMissingDirectoryIsRejected() {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("xray-crash-report-missing-\(UUID().uuidString)", isDirectory: true)
        XCTAssertThrowsError(try XrayCore.setCrashReportDirectory(missing))
    }

    func testEventsDecodeLenientlyAndUnknownKindsSurvive() throws {
        let json = #"""
        {"schemaVersion":1,"pid":42,"startedUnixMs":10,"droppedEvents":3,"futureField":true,
         "events":[
          {"kind":"panic","message":"boom","location":"src/a.rs:1:2","thread":"xray-ffi",
           "backtrace":" 0 Tunnel+0x10\n","unixMs":20,"firstUnixMs":15,"count":2},
          {"kind":"somethingNew","message":"later","unixMs":30}
         ]}
        """#
        let report = try JSONDecoder().decode(XrayCrashReport.self, from: Data(json.utf8))
        XCTAssertEqual(report.droppedEvents, 3)
        XCTAssertEqual(report.events.count, 2)
        XCTAssertEqual(report.events[0].count, 2)
        XCTAssertEqual(report.events[0].firstUnixMs, 15)
        XCTAssertEqual(report.events[0].backtrace, " 0 Tunnel+0x10\n")
        XCTAssertEqual(report.events[1].kind, "somethingNew")
        XCTAssertNil(report.events[1].location)
        XCTAssertEqual(report.events[1].firstUnixMs, 30)
        XCTAssertEqual(report.events[1].count, 1)

        let unsupported = #"{"schemaVersion":2,"events":[]}"#
        XCTAssertThrowsError(
            try JSONDecoder().decode(XrayCrashReport.self, from: Data(unsupported.utf8))
        )
    }
}
