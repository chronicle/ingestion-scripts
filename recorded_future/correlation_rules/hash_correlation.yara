rule rf_hash_correlation {

  meta:
    version = "1.0"
    author = "Recorded Future"
    description = "Correlating Recorded Future URLs network traffic logs"
    severity = "Medium"

  events:
    //This rule does not filter by event type and is likely to be extremely select
    // We reccomend you filter by event types likely to contain SHA-256 hashes
    // Examples: Endpoint logs, windows event logs, vuln scan logs
    $event.target.file.sha256 != ""
    $event.target.file.sha256 = $Recorded_Future_Malicious_File_Detected

    $ioc.graph.metadata.entity_type = "FILE"
    $ioc.graph.metadata.vendor_name = "RECORDED_FUTURE_IOC"
    $ioc.graph.entity.file.sha256 != ""
    $ioc.graph.entity.file.sha256 = $Recorded_Future_Malicious_File_Detected

  match:
    $Recorded_Future_Malicious_File_Detected over 1m

  outcome:
    $risk_score = max($ioc.graph.metadata.threat.risk_score)

  condition:
    $event and $ioc

}
