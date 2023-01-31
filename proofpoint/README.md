# Proofpoint VAP

This script fetches the users who are mostly attacked in a particular organization within a given time period and ingest them into the Chronicle platform.

## Platform Specific Environment Variables
| Variable | Description | Required | Default | Secret |
|---|---|---|---|---|
| CHRONICLE_DATA_TYPE | Log type to push data into the Chronicle platform. | Yes | - | No |
| PROOFPOINT_SERVER_URL | Base URL of Proofpoint Server API gateway. | Yes | - | No |
| PROOFPOINT_SERVICE_PRINCIPLE | Service Principle of Proofpoint platform. | Yes | - | No |
| PROOFPOINT_SECRET | Path of the Google Secret Manager with the version, where the Password of Proofpoint platform is stored. | Yes | - | Yes |
| PROOFPOINT_RETRIEVAL_RANGE | Number indicating from how many days the data should be retrieved. Accepted values are 14, 30 and 90. | No | 30 | No |

## Note
- Proofpoint script retrieval range (PROOFPOINT_RETRIEVAL_RANGE) can be set as 14 days, 30 days or 90 days. This acts as the start date to fetch the data.
- The user can configure cloud scheduler to run the cloud function after every 6 hours to fetch the data of the last 30 days.
- The Proofpoint People API records are updated once in every 24 hours, hence running the script every 6 hours will enable the user to fetch and ingest updated data efficiently with minimum data duplication.
- The Proofpoint API has no provision to fetch only the updated records in the given time range hence data duplication is a possible scenario.