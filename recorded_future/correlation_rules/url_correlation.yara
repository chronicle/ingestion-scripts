rule rf_url_correlation {

  meta:
    version = "1.0"
    author = "Recorded Future"
    description = "Correlating Recorded Future URLs network traffic logs"
    severity = "Medium"

  events:
    //This rule correlates against Network Traffic. You may want to tune it by
    //selecting additional filters or choosing another event_type
    $event.metadata.event_type = "NETWORK_HTTP"
    $event.target.url != ""
    $event.target.url = $Recorded_Future_Malicious_URL_Detected

    $ioc.graph.metadata.entity_type = "URL"
    $ioc.graph.metadata.vendor_name = "RECORDED_FUTURE_IOC"
    $ioc.graph.entity.url != ""
    $ioc.graph.entity.url = $Recorded_Future_Malicious_URL_Detected

  match:
    $Recorded_Future_Malicious_URL_Detected over 1m

  outcome:
    $risk_score = max($ioc.graph.metadata.threat.risk_score)

  condition:
    $event and $ioc

}
