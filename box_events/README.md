# Box Events

This script pulls events from Box and ingests them into Chronicle.

## Platform Specific Environment Variables

| Variable          | Description                                                     | Required | Default | Secret |
| ----------------- | --------------------------------------------------------------- | -------- | ------- | ------ |
| BOX_CLIENT_ID     | Client id of box platform (available in box developer console). | Yes      | -       | No     |
| BOX_CLIENT_SECRET | Client secret of box platform.                                  | Yes      | -       | Yes    |
| BOX_SUBJECT_ID    | User ID or enterprise ID.                                       | Yes      | -       | No     |
| POLL_INTERVAL     | Frequency interval(in minutes) at which the Cloud Function executes. This duration must be same as the cloud scheduler job. | No      | 5       | No     | 

## Resources

- [How to get your API Key](https://support.box.com/hc/en-us/articles/360052055274-Developer-How-to-get-your-API-Key)
