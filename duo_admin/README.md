# Duo Admin

This script is for fetching the logs from DUO platform and ingesting to Chronicle.

## Platform Specific Environment Variables
| Variable                  | Description                                                                                  | Required | Default | Secret |
| ------------------------- | -------------------------------------------------------------------------------------------- | -------- | ------- | ------ |
| DUO_API_DETAILS           | Content of DUO account JSON file.                                                            | Yes      | -       | Yes    |
| POLL_INTERVAL             | Fetch within the last x amount of time, where x can be defined in minutes (for example : 30) | No      | 10       | No     |
