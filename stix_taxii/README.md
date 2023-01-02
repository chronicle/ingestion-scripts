# STIX/TAXII Feed

This script pulls indicators from STIX/TAXII server and ingests them into Chronicle.

## List of Environment Variables
| Variable                   | Description                                                                                                                 | Required | Default | Secret |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------- | -------- | ------- | ------ |
| POLL_INTERVAL              | Frequency interval (in minutes) at which the Cloud Function executes. This duration must be same as the Cloud Scheduler job.| No       | 60      | No     |
| TAXII_VERSION              | The STIX/TAXII version to use. Possible options are 1.1, 2.0, 2.1                                                           | Yes      | -       | No     |
| TAXII_DISCOVERY_URL        | Discovery URL of TAXII server.                                                                                              | Yes      | -       | No     |
| TAXII_COLLECTION_NAMES     | Collections (CSV) from which to fetch the data. Leave empty to fetch data from all of the collections.                      | No       | -       | No     |
| TAXII_USERNAME             | Username required for authentication if any.                                                                                | No       | -       | No     |
| TAXII_PASSWORD_SECRET_PATH | Password required for authentication if any.                                                                                | No       | -       | Yes    |
