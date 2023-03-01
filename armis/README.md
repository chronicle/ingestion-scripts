# Armis Chronicle Integration

This scripts collect the data using API call from the Armis platform for different types of events like alerts, activities, devices, and vulnerabilities.
Furthermore, the collected data will be ingested into Chronicle and parsed by corresponding parsers.

### The overall flow of the script

- Deploying the script to Cloud Function
- Data collection using ingestion script
- Ingest collected data into Chronicle
- Collected data will be parsed through corresponding parsers in Chronicle

### Environment Variables

| Variable | Description | Required | Default | Secret |
| --- | --- | --- | --- | --- |
| CHRONICLE_CUSTOMER_ID | Chronicle customer ID. | Yes | - | No |
| CHRONICLE_REGION | Chronicle region. | Yes | us | No |
| CHRONICLE_SERVICE_ACCOUNT | Contents of the Chronicle ServiceAccount JSON file. | Yes | - | Yes |
| CHRONICLE_NAMESPACE | The namespace that the Chronicle logs are labeled with. | No | - | No |
| POLL_INTERVAL | Frequency interval at which the function executes to get additional log data (in minutes). This duration must be the same as the Cloud Scheduler job interval. | Yes | 10 | No |
| ARMIS_SERVER_URL | Server URL of Armis platform. | Yes | - | No |
| ARMIS_API_SECRET_KEY | Secret key required to authenticate. | Yes | - | Yes |
| HTTPS_PROXY | Proxy server URL. | No | - | No |
| CHRONICLE_DATA_TYPE | Chronicle data type to push data into the Chronicle. | Yes | - | No |

### Setting up the directory

Create a new directory for the cloud function deployment and add the
following files into that directory:

1. *Contents* of ingestion script (i.e. `armis`)
2. `common` directory

### Setting the required runtime environment variables

Edit the .env.yml file to populate all the required environment variables.
Information related to all the environment variables can be found in this file.

#### Using secrets

Environment variables marked as **Secret** must be configured as secrets on
Google Secret Manager. Refer [this](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#create)
page to learn how to create secrets.

Once the secrets are created on Secret Manager, use the secret's resource name
as the value for environment variables. For example:

```
CHRONICLE_SERVICE_ACCOUNT: projects/{project_id}/secrets/{secret_id}/versions/{version_id}
```

#### Configuring the namespace

The namespace that the Chronicle logs are ingested into can be configured by
setting the `CHRONICLE_NAMESPACE` environment variable.

### Deploying the cloud function

Execute the following command from inside the previously created directory to 
deploy the cloud function.

```
gcloud functions deploy <FUNCTION NAME> --gen2 --entry-point main --trigger-http --runtime python39 --env-vars-file .env.yml
```

### Cloud Function Default Specifications

| Variable | Default Value | Description |
| --- | --- | --- |
| Memory | 256 MB | Allocated memory for a specific cloud function. |
| Timeout | 60 seconds | Time Interval for the termination of a cloud function. |
| Region | us-central1 | Region for a cloud function. |
| Minimum instances | 0 | Minimum number of instance for a cloud function. |
| Maximum instances | 100 | Maximum number of instances for a cloud function. |

- The configuration documentation of the above variables can be found here: [link](https://cloud.google.com/functions/docs/configuring)

## Steps to fetch the historical data all at once and then continue with the real-time data collection

- Configure POLL_INTERVAL environment variable in minutes for which the historical data needs to be fetched.
- As the cloud function is configured, the function can be triggered using a scheduler or manually by executing the command in Google Cloud CLI.

## Resources

- [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install)
- [Deploying cloud functions from local machine](https://cloud.google.com/functions/docs/deploying/filesystem)