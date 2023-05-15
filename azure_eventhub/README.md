# Azure Event Hub

This script fetches the Azure EventHub data and ingests it into Chronicle.

## Steps to deploy Azure Function
1. Login into the Microsoft Azure Portal (https://portal.azure.com/).
2. From the Azure portal search bar, search for **Deploy a custom template** Azure service and select the service from the available options. This step will redirect to the **Custom deployment** page.
3. Download the ARM template **azuredeploy_Connector_EventHub_AzureFunctions.json** file from the repository.
4. Click on **Build your own template in the editor** option. This step will open the **Edit template** page.
5. Click on **Load file** option and upload the ARM template file downloaded at step 3.
6. Select **Save**.
7. You see the blade for providing the deployment values. Select the preferred Subscription, Resource Group, Region and provide the Function specific values. Description for all the function-specific parameters are provided in the below table.
8. Click **Review + Create** button.
9. Click **Create** to deploy.

Now the deployed Azure function will trigger for new data in Azure Event Hub and ingest them into Chronicle.

## Platform Specific Parameters in Azure Function

| Parameter                    | Description                               | Required | Default |
| ---------------------------  | ----------------------------------------- | -------- | ------- |
| Function Name                | Function names allow only alphanumeric characters. Special characters are not allowed and length of the name should be less than or equal to 11 characters.            | Yes      | Chronicle       |
| Eventhub Namespace         | Namespace of the Eventhub from which data should be collected.         | Yes      | -       |
| Eventhub Name           |  Name of the Eventhub from which data should be collected.                     | Yes      | -       |
| Shared Access Key                | Primary key of the Eventhub namespace. | Yes       | -      |
| Chronicle Customer ID                   | Customer ID of Google Chronicle.                    | Yes      | -       |
| Chronicle Service Account                  | Provide the Google Chronicle Service Account JSON.                   | Yes      | -       |
| Chronicle Region                  | Specify the Google Chronicle region.                   | Yes      | us       |
| Chronicle Data Type                  | Specify the log type to ingest data into Chronicle.                   | Yes      | -       |

