# OneLogin Users

This script pulls events from OneLogin and ingests them into Chronicle.

## Platform Specific Environment Variables

| Variable       | Description                                                     | Required | Default |
| -------------- | --------------------------------------------------------------- | -------- | ------- |
| CLIENT_ID      | Client ID of OneLogin platform                                  | Yes      | -       | No     |
| CLIENT_SECRET  | Client Secret of OneLogin platform                              | Yes      | -       | Yes    |
| POLL_INTERVAL  | Frequency interval(in minutes) at which the Cloud Function executes. This duration must be same as the cloud scheduler job. | No      | 30      | No    |
| TOKEN_ENDPOINT | URL for token request.                                          | No       | https://api.us.onelogin.com/auth/oauth2/v2/token       | No     |
