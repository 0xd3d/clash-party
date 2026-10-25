import Foundation
@main struct TunnelHealthChecks {
 static func main() throws {
  let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer {try? FileManager.default.removeItem(at:root)}
  let store=TunnelHealthStore(directoryURL:root)
  precondition(store.read()==nil)
  var first=try store.begin(processID:11,now:Date(timeIntervalSince1970:1000))
  first.heartbeatAt=Date(timeIntervalSince1970:1030)
  first.physFootprintBytes=1234
  first.peakPhysFootprintBytes=4321
  let encoder=JSONEncoder();encoder.dateEncodingStrategy = .iso8601
  var oldJSON=try JSONSerialization.jsonObject(with:encoder.encode(first)) as! [String:Any]
  oldJSON.removeValue(forKey:"peakPhysFootprintBytes")
  let decoder=JSONDecoder();decoder.dateDecodingStrategy = .iso8601
  let legacy=try decoder.decode(TunnelHealthRecord.self,from:JSONSerialization.data(withJSONObject:oldJSON))
  precondition(legacy.peakPhysFootprintBytes==nil && legacy.physFootprintBytes==1234)
  try store.write(first)
  let second=try store.begin(processID:12,now:Date(timeIntervalSince1970:1100))
  precondition(second.sessionID != first.sessionID)
  precondition(store.read(previous:true)==first)
  precondition(store.read()?.processID==12)
  var stopped=second;stopped.event="stopReceived";stopped.stopReason="userInitiated"
  try store.write(stopped)
  _=try store.begin(processID:13)
  precondition(store.read(previous:true)?.stopReason=="userInitiated")
  try Data("invalid".utf8).write(to:root.appendingPathComponent("tunnel-health.json"))
  precondition(store.read()==nil)
  _=try store.begin(processID:14)
  precondition(store.read(previous:true)?.stopReason=="userInitiated")
  let underlying=NSError(domain:"Cause",code:17,userInfo:["token":"mustNotAppear"])
  let outer=NSError(domain:"NEVPNConnectionErrorDomain",code:12,userInfo:[NSUnderlyingErrorKey:underlying])
  precondition(TunnelDisconnectErrorSummary.describe(outer)=="NEVPNConnectionErrorDomain/12 -> Cause/17")
  print("PASS: peak memory and legacy records survive; abnormal session evidence survives restart; normal stop remains identifiable; malformed/missing health safe; underlying errors bounded and exclude userInfo.")
 }
}
