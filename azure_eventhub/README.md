# Azure Event Hub

This script fetches the Azure EventHub data and ingests it into Chronicle.

## Steps to deploy Azure Function
1. Download the data connector file i.e **Azure_eventhub_API_function_app.json** from the repository.
2. Sign in to your Microsoft Azure portal.
3. Navigate to Microsoft Sentinel --> Select your workspace from the list --> Select Data Connector in the configuration section.
  - **Note:** Set the following flag as true in the url **feature.BringYourOwnConnector=true&feature.experimentationflights=ConnectorsKO**
  - **Example:** https://portal.azure.com/?feature.BringYourOwnConnector=true&feature.experimentationflights=ConnectorsKO#view...
4. Find the **Import** button on the page and import the data connector file downloaded in step 1.
5. Click the **Deploy to Azure** button to deploy your function and follow the steps mentioned on the same page.
6. Select the preferred Subscription, Resource Group and Location and provide the required values.
7. Click **Review + Create** button.
8. Click **Create** to deploy.

Now the deployed Azure function will trigger for new data in Azure Event Hub and ingest them into Chronicle.
