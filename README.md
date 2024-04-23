# Google Security Operations 3p Ingestion Scripts

## Deploying the Cloud Function

### Setting up the directory

Create a new directory for the cloud function deployment and add the following
files into that directory:

1.  *Contents* of the desired platform (i.e. `OneLogin_User`)
2.  `common` directory

### Setting the required runtime environment variables

Edit the .env.yml file to populate all the required environment variables.
Information related to all the environment variables can be found in the
README.md file.

#### Common runtime environment variables

Following is the table listing all the Google Security Operations related runtime environment
variables that must be configured for all the ingestion scripts.

| Variable                  | Description    | Required | Default | Secret |
| ------------------------- | -------------- | -------- | ------- | ------ |
| POLL_INTERVAL             | Poll interval  | Yes      | -       | No     |
:                           : for the cloud  :          :         :        :
:                           : function.      :          :         :        :
| CHRONICLE_CUSTOMER_ID     | Chronicle      | Yes      | -       | No     |
:                           : customer Id.   :          :         :        :
| CHRONICLE_REGION          | Chronicle      | Yes      | us      | No     |
:                           : region.        :          :         :        :
| CHRONICLE_SERVICE_ACCOUNT | Contents of    | Yes      | -       | Yes    |
:                           : the Chronicle  :          :         :        :
:                           : ServiceAccount :          :         :        :
:                           : JSON file.     :          :         :        :

#### Using secrets

Environment variables marked as **Secret** must be configured as secrets on
Google Secret Manager. Refer
[this](https://cloud.google.com/secret-manager/docs/creating-and-accessing-secrets#create)
page to learn how to create secrets.

Once the secrets are created on Secret Manager, use the secret's resource name
as the value for environment variables. For example:

```
 CHRONICLE_SERVICE_ACCOUNT: projects/{project_id}/secrets/{secret_id}/versions/{version_id}
```

#### Configuring the namespace

The namespace that the Google Security Operations logs are ingested into can be configured by
setting the `CHRONICLE_NAMESPACE` environment variable.

### Deploying the cloud function

Execute the following command from inside the previously created directory to
deploy the cloud function.

```
gcloud functions deploy <FUNCTION NAME> --entry-point main --trigger-http --runtime python39 --env-vars-file .env.yml
```

## Support

These scripts are provided as examples and are not officially supported. We
welcome feedback on how we can improve them. To submit feedback, go to the
[Chronicle Ingestion Script documentation](https://cloud.google.com/chronicle/docs/ingestion/ingest-using-cloud-functions)
and click "Send Feedback".

## Resources

-   [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install)
-   [Deploying cloud functions from local machine](https://cloud.google.com/functions/docs/deploying/filesystem)
