# DomainTools Chronicle Integration

The Chronicle App for DomainTools fetches real-time events from the Chronicle and extracts domains for further enrichment from DomainTools APIs. This app allows users to leverage the ad-hoc enrichment of domains when in need. This also contains Looker dashboards where users can visualize different metrics

### The overall flow of the script:
- Deploying the script to Cloud Function
- Data collection using ingestion script from the Chronicle
- Enrich Domains from the DomainTools
- Fetch Subdomains from DNSDB, if needed
- Ingest enriched domain data into Chronicle
- Collected data will be parsed through corresponding parsers in Chronicle

### Pre-Requisites
- Chronicle console and Chronicle service account.
- DomainTools credentials (API username, API key, DNSDB API key)
- GCP Project with the below required permissions:
  - GCP user and project service account should have Owner permissions
- GCP Services
- Memory store - Redis
- Cloud function (4-core CPU or higher is recommended for cloud function configuration)
- GCS bucket
- Secret Manager
- Cloud Scheduler
- Serverless VPC access

### Environment Variables

| Variable | Description | Required | Default | Secret |
| --- | --- | --- | --- | --- |
| CHRONICLE_CUSTOMER_ID | Chronicle customer Id. | Yes | - | No |
| CHRONICLE_REGION | Chronicle region. | No | us | No |
| CHRONICLE_SERVICE_ACCOUNT | Contents of the Chronicle ServiceAccount JSON file. | Yes | - | Yes |
|GCP_BUCKET_NAME | Name of the created GCP bucket. | Yes | - | No |
| REDIS_HOST | IP of the created Redis memory store. | Yes | - | No |
| REDIS_PORT | Port of the created Redis memory store. | Yes | - | No |
| DOMAINTOOLS_API_USERNAME | Copied resource name value of DomainTools API username secret from the secret manager. | Yes | - | Yes |
| DOMAINTOOLS_API_KEY | Copied resource name value of DomainTools API key secret from the secret manager. | Yes | - | Yes |
| DNSDB_API_KEY | Copied resource name value of DNSDB API key secret from the secret manager. | No | - | Yes |
| FETCH_SUBDOMAINS_FOR_MAX_DOMAINS | Fetch subdomains for the maximum number of domains. | No | 2000 | No |
| LOG_FETCH_DURATION | Time duration in the seconds to fetch events from the Chronicle. Provide an integer value. Eg. If the user wants to fetch the logs every 5 minutes then the user needs to specify 300 seconds. | Yes | - | No |
|CHECKPOINT_FILE_PATH | Path of the checkpoint file if provided in the bucket. If provided, events from the specified will be fetched from the chronicle. If the file is present directly into the bucket then the user only needs to give the file name for this variable. If the file is given inside a folder then the path of the folder along with the file name needs to be specified like folderName/fileName. | No | - | No |
| FETCH_URL_EVENTS | Flag to fetch URL-aware events from the Chronicle. Accepted values [true, false] | No | false | No |
| LOG_TYPE_FILE_PATH | Path of Log type file name if provided in the bucket. If provided, events from those log types will be fetched from the Chronicle. Otherwise, all log types will be considered. Provide comma-separated values in the file. If the file is present directly into the bucket then the user only needs to give the file name for this variable. If the file is given inside a folder then the path of the folder along with the file name needs to be specified like folderName/fileName. | No | All log types | No |
| PROVISIONAL_TTL | TTL(time to leave) value if the domain has Evidence key and value as the provisional in the API response. Provide an integer value for this. If provided that will be considered, otherwise default 1 day will be considered. | No | 1 day | No |
| NON_PROVISIONAL_TTL | TTL(time to leave) value for all other domains. Provide an integer value for this. If provided that will be considered, otherwise default 30 days will be considered. | No | 30 day | No |
| ALLOW_LIST | Name of the allow list reference list created in the Chronicle. | No | - | No |
| MONITORING_LIST | Name of the monitoring list reference list created in the Chronicle. | No | - | No |
| MONITORING_TAGS | Name of the monitoring tags reference list created in the Chronicle. | No | - | No |
| BULK_ENRICHMENT | Name of the bulk enrichment reference list created in the Chronicle. | No | - | No |  

### Creating zip of the cloud function
Create a zip file of the cloud function with the contents of the following files:
1. Contents of the ingestion script (i.e. `domaintools`)
2. `common` directory

### Command based(automated) deployment of the required GCP resources
1. Perform each steps mention below to setup resource(s):
   1. Create Redis and Bucket: 
      - Log in to the Google Cloud Console "https://console.cloud.google.com/"
      - Select the project created for the DomainTools from the upper left side dropdown.
      - Click on the Activate Cloud Shell button.
      - Click on the Open Editor button after Cloud Shell opens successfully.
      - Create a new file and add the below code to the file. The file type should be jinja. (e.g. resource.jinja)
        ```jinja
        resources:
        - name: {{ properties["name"] }}
          type: gcp-types/redis-v1:projects.locations.instances
          properties:
             parent: projects/{{ env["project"] }}/locations/{{ properties["region"] }}
             instanceId: {{ properties["name"] }}
             authorizedNetwork: projects/{{ env["project"] }}/global/networks/default
             memorySizeGb: {{ properties["memory"] }}
             tier: STANDARD_HA
             {% if properties["displayName"] %}
             displayName: {{ properties["displayName"] }}
             {% endif %}
        ```
      - Create another file and copy below code to that file. The file should be in yaml format. (e.g. config.yaml)
        ```yaml
          imports:
          - path: RESOURCE_FILE_NAME
          resources:
          - name: REDIS_INSTANCE_NAME
            type: RESOURCE_FILE_NAME
            properties:
             name: REDIS_INSTANCE_NAME
             region: us-central1
             memory: 2
             displayName: redis_display_name
          - name: BUCKET_NAME
            type: storage.v1.bucket
            properties:
            location: US
         ```
          - **RESOURCE_FILE_NAME**: Name of the created resource file(e.g. resource.jinja).  
          - **REDIS_INSTANCE_NAME**: Unique name of the Redis instance.  
          - **BUCKET_NAME**: Unique name of the bucket.
   
      - Now click on the Open Terminal and hit the below command.

         `gcloud deployment-manager deployments create NAME_OF_DEPLOY --config NAME_OF_CONFIG_FILE`

         - **NAME_OF_DEPLOY**: Unique name of the deployment manager.

         - **NAME_OF_CONFIG_FILE**: Name of the created config file (e.g. config.yaml).

         If deployment is unsuccessful, a user has to delete the deployment manager instance and create it again. To delete the deployment manager, hit the below command.

         `gcloud deployment-manager deployments delete NAME_OF_DEPLOY`
      
   2. Create a Serverless VPC Access:
      - Hit the below command in the terminal after the deployment manager is created successfully.
      
        `gcloud compute networks vpc-access connectors create VPC_NAME --network default  --region REGION --range IP_RANGE`
      - **VPC_NAME**: Unique name of the VPC.
      - **REGION**: A region for your connector. Values can be  us-central1, us-west1, etc.
      - **IP_RANGE**: An unreserved internal IP network and a /28 of unallocated space is required. The value supplied is the network in CIDR notation (10.0.0.0/28). This IP range must not overlap with any existing IP address reservations in your VPC network.
   3. Create a Cloud function
      - Navigate to the bucket and open the bucket created for the DomainTools. Upload the cloud function zip file in the bucket.
      - Hit the below command in the terminal after the VPC network is created successfully.
  
          `gcloud functions deploy CLOUD_FUNCTION_NAME --set-env-vars ENV_NAME1=ENV_VALUE1,ENV_NAME2=ENV_VALUE2,ENV_NAME3=  --gen2 --runtime=python311 --region=us-central1 --source=SOURCE_OF_FUNCTION  --entry-point=main --service-account=SERVICE_ACCOUNT_EMAIL --trigger-http --no-allow-unauthenticated --memory=8GiB --vpc-connector=VPC_NAME --egress-settings=private-ranges-only --timeout=3600s`

      - **CLOUD_FUNCTION_NAME**: Unique name of the cloud function.
      - **SOURCE_OF_FUNCTION**: gsutil URI of the cloud function zip in cloud storage. (e.g. gs://domaintools/function.zip) where the domaintools is the name of the created bucket and function.zip is the cloud function zip file.
      - **SERVICE_ACCOUNT_EMAIL**: Email of the created service account of the project.
      - **VPC_NAME**: Name of the created VPC Network.
      - **ENV_NAME1**=**ENV_VALUE1**: Name and value of the environment variable to be created. For optional environment variables, provide **ENV_NAME=**

         The user has to provide all the required environment variables while creating the cloud function. The optional environment variables can also be provided after the cloud function is deployed by editing the cloud function.
   4. Create a Cloud Scheduler:

      - Hit the below command in the terminal after the cloud function is created successfully.
  
         `gcloud scheduler jobs create http SCHEDULER_NAME --schedule="CRON_TIME" --uri="CLOUD_FUNCTION_URL" --attempt-deadline=30m --oidc-service-account-email=SERVICE_ACCOUNT_EMAIL --location=LOCATION`

      - **SCHEDULER_NAME**: Unique name of the cloud scheduler.
      - **CRON_TIME**: Cron expression for the scheduler to run in every interval. (eg. */10 * * * *)
      - **CLOUD_FUNCTION_URL**: URL of the created cloud function. For URL, navigate to the Cloud Functions page and open the existing cloud function created for the DomainTools.
      - **SERVICE_ACCOUNT_EMAIL**: Email of the created service account of the project.
      - **LOCATION**: A region for your connector. Values can be **us-central1**, **us-west1**, etc 
  
2. After a successful deployment of the required resources of the GCP, the cloud function will fetch domain/URL aware (domain/URL present) events from the Chronicle as per the Cloud scheduler.
3. The domain will be extracted from the events from the Chronicle and will be enriched from the DomainTools.
4. A unique first 10  subdomains of the enriched domains will be fetched from the DNSDB if the DNSDB API key is provided in the environment variable.
5. If allow list is provided in the environment variable, the domains provided in the allow list will be excluded from the enrichment.
6. The enriched domains will be stored in the Redis memory store with the TTL(time to leave). When the TTL value is passed, the domain will be removed from the Redis memory store.
7. An enriched domain event will be ingested and parsed in the Chronicle.

### Using secrets

Environment variables marked as **Secret** must be configured as secrets on
Google Secret Manager. Refer [this](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#create)
page to learn how to create secrets.

Once the secrets are created on Secret Manager, use the secret's resource name
as the value for environment variables. For example:
```
CHRONICLE_SERVICE_ACCOUNT: projects/{project_id}/secrets/{secret_id}/versions/{version_id}
```

### Create List in Chronicle
1. Open the Chronicle Console.

2. Click on the “Search” option in the sidebar panel.

   ![Chronicle UI](images\chronicle.png)

3. Click on the “Lists” option. The List Manager section will open.

4. Now, Click on the create button.

5. Specify the list name (TITLE), description and content (ROWS). Specify the content with one item on each line.
   
   ![Reference List](images\reference_list.png)

6. The user has to create reference lists for allow list, monitoring list, monitoring tags and bulk enrichment ad-hoc script execution. The name of each list must be specified within the environment variable corresponding to its list type.

### Create Rules in Chronicle to generate detections
1. Open the Chronicle console.

2. Click on the Rules & Detections option in the sidebar panel.

3. Click on the Rules Editor in the navigation bar.

4. Click on the NEW button to create a rule. Create rules for the High Risk Domain, Medium Risk Domain, Young Domain, Monitoring Domain, and Monitoring Tag Domain with name mentioned in the attached screenshot.

5. Add the below code to the following Rule

   - high_risk_domain_observed

     ![High Risk Rule](images\high_risk_rule.png)
   - medium_risk_domain_observed

     ![Medium Risk Rule](images\medium_risk_rule.png)
   - young_domain

     ![Young Domain Rule](images\young_domain_rule.png)
   - monitoring_list_domain 

     ![Monitoring List Rule](images\monitoring_list_rule.png)
   - monitoring_tags_domain_observed

     ![Monitoring Tag Rule](images\monitoring_tags_rule.png)


### Ad-hoc script execution

1. Allowlist Management

   * The domains provided in the allow list will be excluded from the enrichment.
   * A user has to create and manage a list from the Chronicle.
   * A list created in the Chronicle needs to be provided in the environment variable of the created cloud function.
   * Now go to the Testing tab of the cloud function and enter the {“allow_list”: “true”} parameter in the Configure triggering event and click on the TEST THE FUNCTION button. If the TEST THE FUNCTION button is not present, click on the RUN IN CLOUD SHELL and click the enter.
   * The dummy events of the allow list domains will be ingested in the Chronicle.
   * When the user updates the list, a user needs to execute the ad-hoc script again.


2. Monitoring List Management

   * The domains provided in the monitoring list will be enriched from the DomainTools and create the detection in the Chronicle if a monitoring list domain is observed in the user network.
   * A user has to create and manage a list from the Chronicle.
   * A list created in the Chronicle needs to be provided in the environment variable of the created cloud function.
   * Now go to the Testing tab of the cloud function and enter the {“monitoring_list": “true”} parameter in the Configure triggering event and click on the TEST THE FUNCTION button. If the TEST THE FUNCTION button is not present, click on the RUN IN CLOUD SHELL and click the enter.
   * The enriched domain event with additional monitoring fields for the monitoring list domains will be ingested in the Chronicle.
   * When the user updates the list, a user needs to execute the ad-hoc script again.


3. Monitoring Tags

   * The detection will be created in the Chronicle if tags provided in the monitoring list are present in the enriched domain event.
   * A user has to create and manage a list from the Chronicle.
   * A list created in the Chronicle needs to be provided in the environment variable of the created cloud function.
   * Now go to the Testing tab of the cloud function and enter the {monitoring_tags: “true”} parameter in the Configure triggering event and click on the TEST THE FUNCTION button. If the TEST THE FUNCTION button is not present, click on the RUN IN CLOUD SHELL and click the enter.
   * The dummy events of the monitoring tags will be ingested in the Chronicle.
   * When the user updates the list, a user needs to execute the ad-hoc script again.


4. Single or Bulk Enrichment

   * The domains provided in the bulk enrichment list will be enriched from the DomainTools with on-the-go requests.
   * A user has to create and manage a list from the Chronicle.
   * A list created in the Chronicle needs to be provided in the environment variable of the created cloud function.
   * Now go to the Testing tab of the cloud function and enter the {“bulk_enrichment”: “true”}  parameter in the Configure triggering event and click on the TEST THE FUNCTION button. If the TEST THE FUNCTION button is not present, click on the RUN IN CLOUD SHELL and click enter.
   * The enriched domain event for the bulk enrichment domains will be ingested in the Chronicle.
   * When the user updates the list, a user needs to execute the ad-hoc script again.

![Adhoc Parameters](images\adhoc_parameters.png)

## Resources

- [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install)
- [Deploying cloud functions from local machine](https://cloud.google.com/functions/docs/deploying/filesystem)