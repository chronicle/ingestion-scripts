# OneLogin Events

This script pulls events from OneLogin and ingests them into Chronicle.

## Platform Specific Environment Variables

| Variable       | Description                                                     | Required | Default | Secret |
| -------------- | --------------------------------------------------------------- | -------- | ------- | ------ |
| CLIENT_ID      | Client id of OneLogin platform                                  | Yes      | -       | No     |
| CLIENT_SECRET  | Client secret of OneLogin platform.                             | Yes      | -       | Yes    |
| TOKEN_ENDPOINT | URL for token request.                                          | No       | https://api.us.onelogin.com/auth/oauth2/v2/token       | No     |
