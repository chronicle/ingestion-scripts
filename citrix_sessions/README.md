# Citrix Sessions

This script collects citrix metadata which helps in user traffic monitoring on
citrix environments.

## Platform Specific Environment Variables

| Variable                    | Description                               | Required | Default | Secret |
| --------------------------- | ----------------------------------------- | -------- | ------- | ------ |
| CITRIX_CLIENT_ID            | Client ID of Citrix platform.             | Yes      | -       | No     |
| CITRIX_CLIENT_SECRET        | Client Secret of Citrix platform.         | Yes      | -       | Yes    |
| CITRIX_CUSTOMER_ID          | ID of the customer.                       | Yes      | -       | No     |
| POLL_INTERVAL               | Frequency interval(in minutes) at which the Cloud Function executes. This duration must be same as the cloud scheduler job. | No       | 30      | No     |
| URL_DOMAIN                  | Citrix Cloud Endpoint.                    | Yes      | -       | No     |
