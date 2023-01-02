## DESCRIPTION
---

**This script is for fetching message information from the PUBSUB Subscriptions and ingesting to Chronicle.**

## PREREQUISITE
---
This Cloud Function expects the data from PUBSUB in the JSON format. If the message is not received in the expected format, the function would skip the message and continue the data collection.
<br>Since there can be multiple subscriptions, the user can deploy the Cloud Function once, and configure multiple Cloud Schedulers to collect messages from respective subscriptions.</br>


**List of Environment variables:**
<br>Below details need to be provided in the Body section of Cloud Scheduler to allow the ingestion script for data collection.<br>NOTE: The details need to be provided in the JSON format only.</br>

| Variable            | Description                                              | Required | Default | Secret |
| ------------------- | -------------------------------------------------------- | -------- | ------- | ------ |
| PROJECT_ID          | PUBSUB project ID.                                       | Yes      | -       | No     |
| SUBSCRIPTION_ID     | PUBSUB Subscription ID.                                  | Yes      | -       | No     |
| CHRONICLE_DATA_TYPE | Log type to be provided while pushing data to Chronicle. | Yes      | -       | No     |
