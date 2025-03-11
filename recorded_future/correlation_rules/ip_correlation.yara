rule rf_ip_correlation {

  meta:
    version="1.0"
    author = "Recorded Future"
    description = "Correlating Recorded Future malicious IPs with network traffic logs"
    severity = "Medium"

  events:
    //This rule correlates against Network Traffic. You may want to tune it by
    //selecting additional filters or choosing another event_type
    $event.metadata.event_type = "NETWORK_CONNECTION"
    $event.target.ip != ""
    $event.target.ip = $Recorded_Future_Malicious_IP_Detected

    $ioc.graph.metadata.vendor_name = "RECORDED_FUTURE_IOC"
    $ioc.graph.metadata.entity_type = "IP_ADDRESS"
    $ioc.graph.entity.ip != ""
    $ioc.graph.entity.ip = $Recorded_Future_Malicious_IP_Detected

  match:
    $Recorded_Future_Malicious_IP_Detected over 1m

  outcome:
    $risk_score = max($ioc.graph.metadata.threat.risk_score)

  condition:
    $event and $ioc

}
