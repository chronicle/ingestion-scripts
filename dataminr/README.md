# Dataminr Chronicle Integration

This script collects the alert data using API calls from the Dataminr platform.
Furthermore, the collected data will be ingested into Chronicle and parsed by corresponding parsers.
### The overall flow of the script:
- Deploying the script to Cloud Function
- Data collection using ingestion script
- Ingest collected data into Chronicle
- Collected data will be parsed through corresponding parsers in Chronicle

### Environment Variables

| Variable | Description | Required | Default | Secret |
| --- | --- | --- | --- | --- |
| CHRONICLE_CUSTOMER_ID | Chronicle customer Id. | Yes | - | No |
| CHRONICLE_REGION | Chronicle region. | Yes | us | No |
| CHRONICLE_SERVICE_ACCOUNT | Path of the Google Secret Manager with the version, where the Service Account is stored. | Yes | - | Yes |
| CHRONICLE_NAMESPACE | The namespace that the Chronicle logs are labeled with. | No | - | No |
| DATAMINR_CLIENT_ID | Dataminr client id required to authenticate. | Yes | - | No |
| DATAMINR_CLIENT_SECRET | Dataminr client secret required to authenticate. | Yes | - | Yes |
| DATAMINR_ALERT_LIMIT | The size of alerts to fetch in one API call | No | 40 | No |
| DATAMINR_WATCHLIST_NAMES | Comma separated Dataminr watch list names. | No | All | No |
| DATAMINR_ALERT_QUERY | Terms to search within Dataminr Alerts. | No |- | No |
| GCP_BUCKET_NAME | GCP bucket name to store checkpoint. | Yes | - | No |
| HTTPS_PROXY | Proxy server URL | No | - | No |

### Setting up the directory

Create a new directory for the cloud function deployment and add the
following files into that directory:

1. *Contents* of ingestion script (i.e. `dataminr_ingestion_script`)
2. `common` directory

### Setting the required runtime environment variables

Edit the .env.yml file to populate all the required environment variables.
Information related to all the environment variables can be found in the
README.md file.

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
gcloud functions deploy <FUNCTION NAME> --gen2 --entry-point main --trigger-http --runtime python310 --env-vars-file .env.yml
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

## Resources

- [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install)
- [Deploying cloud functions from local machine](https://cloud.google.com/functions/docs/deploying/filesystem)

## Mappings

### Alerts Field Mapping

| UDM Field Name | RawLog Field Name | Logic |
| --- | --- | --- |
| about.labels[alertType_color] | alertType.color | |
| about.labels[alertType_id] | alertType.id | |
| about.labels[alertType_name] | alertType.name | |
| about.labels[availableRelatedAlerts] | availableRelatedAlerts | |
| about.labels[eventVolume] | eventVolume | |
| about.labels[headerColor] | headerColor | |
| about.labels[headerLabel] | headerLabel | |
| about.labels[parentAlertId] | parentAlertId | |
| about.labels[subCaption_bullets_content] | subCaption.bullets.content | |
| about.labels[subCaption_bullets_media] | subCaption.bullets.media | |
| about.labels[subCaption_bullets_source] | subCaption.bullets.source | |
| about.labels[watchlistsMatchedByType_externalTopicIds] | watchlistsMatchedByType.externalTopicIds | |
| about.labels[watchlistsMatchedByType_id] | watchlistsMatchedByType.id | |
| about.labels[watchlistsMatchedByType_locationGroups_id] | watchlistsMatchedByType.locationGroups.id | |
| about.labels[watchlistsMatchedByType_locationGroups_locations_id] | watchlistsMatchedByType.locationGroups.locations.id | |
| about.labels[watchlistsMatchedByType_locationGroups_name] | watchlistsMatchedByType.locationGroups.name | |
| about.labels[watchlistsMatchedByType_name] | watchlistsMatchedByType.name | |
| about.labels[watchlistsMatchedByType_type] | watchlistsMatchedByType.type | |
| about.labels[watchlistsMatchedByType_userProperties_omnilist] | watchlistsMatchedByType.userProperties.omnilist | |
| about.labels[watchlistsMatchedByType_userProperties_uiListType] | watchlistsMatchedByType.userProperties.uiListType | |
| about.labels[watchlistsMatchedByType_userProperties_watchlistColor] | watchlistsMatchedByType.userProperties.watchlistColor | |
| about.location.name | watchlistsMatchedByType.locationGroups.locations.name | |
| about.location.region_coordinates | watchlistsMatchedByType.locationGroups.locations.lat, watchlistsMatchedByType.locationGroups.locations.lng | |
| extensions.vulns.vulnerabilities.about.application | metadata.cyber.vulnerabilities.products.productName | |
| extensions.vulns.vulnerabilities.about.platform_version | metadata.cyber.vulnerabilities.products.productVersion | |
| extensions.vulns.vulnerabilities.cve_description | metadata.cyber.vulnerabilities.exploitPocLinks | |
| extensions.vulns.vulnerabilities.cve_id | metadata.cyber.vulnerabilities.id | |
| extensions.vulns.vulnerabilities.cvss_base_score | metadata.cyber.vulnerabilities.cvss | |
| extensions.vulns.vulnerabilities.vendor | metadata.cyber.vulnerabilities.products.productVendor | |
| idm.is_alert | - | This field is set `true` |
| metadata.description | caption | |
| metadata.event_timestamp | eventTime | |
| metadata.event_type | - | This field is set to SCAN_UNCATEGORIZED if principal.ip is available else GENERIC_EVENT |
| metadata.product_log_id | alertId | |
| metadata.url_back_to_product | expandAlertURL | |
| network.asn | metadata.cyber.asns | |
| network.organization_name | metadata.cyber.orgs | |
| principal.application | metadata.cyber.products | |
| principal.ip | metadata.cyber.addresses.ip | |
| principal.labels[eventLocation_probability] | eventLocation.probability | |
| principal.labels[eventLocation_radius] | eventLocation.radius | |
| principal.labels[eventMapLargeURL] | eventMapLargeURL | |
| principal.labels[eventMapSmallURL] | eventMapSmallURL | |
| principal.labels[expandMapURL] | expandMapURL | |
| principal.labels[location_places] | eventLocation.places | |
| principal.labels[metadata_cyber_addresses_%{index}_version] | metadata.cyber.addresses.version | |
| principal.labels[relatedTerms] | relatedTerms.text, relatedTerms.url | |
| principal.labels[relatedTermsQueryURL] | relatedTermsQueryURL | |
| principal.location.name | eventLocation.name | |
| principal.location.region_coordinates | eventLocation.coordinates | |
| principal.port | metadata.cyber.addresses.port | |
| principal.resource.name | post.media.link | |
| security_result.about.file.sha1 | metadata.cyber.hashValues.type, metadata.cyber.hashValues.value | |
| security_result.about.file.sha256 | metadata.cyber.hashValues.type, metadata.cyber.hashValues.value | |
| security_result.about.labels[categories_topicType] | categories.topicType | |
| security_result.about.labels[sectors_id] | sectors.id | |
| security_result.about.labels[sectors_idStr] | sectors.idStr | |
| security_result.about.labels[sectors_name] | sectors.name | |
| security_result.about.labels[sectors_retired] | sectors.retired | |
| security_result.about.labels[sectors_topicType] | sectors.topicType | |
| security_result.about.location.city | companies.locations.city | |
| security_result.about.location.country_or_region | companies.locations.country, companies.locations.state.symbol | |
| security_result.about.location.state | companies.locations.state.name | |
| security_result.about.resource.attribute.labels[companies_id] | companies.id | |
| security_result.about.resource.attribute.labels[companies_idStr] | companies.idStr | |
| security_result.about.resource.attribute.labels[companies_requested] | companies.requested | |
| security_result.about.resource.attribute.labels[companies_retired] | companies.retired | |
| security_result.about.resource.attribute.labels[companies_ticker] | companies.ticker | |
| security_result.about.resource.attribute.labels[companies_topicType] | companies.topicType | |
| security_result.about.resource.attribute.labels[dm_bucket_%{id}] | companies.dm_bucket.id, companies.dm_bucket.name | |
| security_result.about.resource.attribute.labels[dm_sector_%{id}] | companies.dm_sector.id, companies.dm_sector.name | |
| security_result.about.resource.attribute.labels[locations_postalCode] | companies.locations.postalCode | |
| security_result.about.resource.name | companies.name | |
| security_result.about.url | metadata.cyber.URLs | |
| security_result.associations.name | metadata.cyber.malwares | |
| security_result.associations.type | - | This is set to `MALWARE` if metadata.cyber.malwares is available |
| security_result.category | - | This field is set to `POLICY_VIOLATION` if `categories.name` is equal to "Cybersecurity - Policy" or  "Government, Policy, & Political Affairs", for "Cybersecurity - Threats & Vulnerabilities" or "Cybersecurity - Crime & Malicious Activity" or "Threats & Precautions" or "Threats" values it is set to `NETWORK_MALICIOUS`,  for "Cybersecurity" value it is set to `NETWORK_SUSPICIOUS`, for "Email and Web Servers" value it is set to `MAIL_PHISHING`, for "Data Exposure and Breaches" value it is set to `DATA_EXFILTRATION`, for values containing "Malware/Phishing/Ransomware" words it is set to `PHISHING`, for "Fraud" value it it set to `NETWORK_SUSPICIOUS` else it is set to `UNKNOWN_CATEGORY` |
| security_result.category | - | This value is set to `SOFTWARE_MALICIOUS` if metadata.cyber.malwares is available |
| security_result.category_details | categories.name | |
| security_result.detection_fields[categories_id] | categories.id | |
| security_result.detection_fields[categories_idStr] | categories.idStr | |
| security_result.detection_fields[categories_path] | categories.path | |
| security_result.detection_fields[categories_requested] | categories.requested | |
| security_result.detection_fields[categories_retired] | categories.retired | |
| security_result.threat_name | metadata.cyber.threats | |
| target.application | source.channels.0 | |
| target.labels[entityName] | source.entityName | |
| target.labels[post_languages_lang] | post.languages.lang | |
| target.labels[post_languages_position] | post.languages.position | |
| target.labels[post_link] | post.link | |
| target.labels[post_text] | post.text | |
| target.labels[post_translatedText] | post.translatedText | |
| target.labels[publisherCategory_color] | publisherCategory.color | |
| target.labels[publisherCategory_name] | publisherCategory.name | |
| target.labels[publisherCategory_shortName] | publisherCategory.shortName | |
| target.labels[source_verified] | source.verified | |
| target.resource.attribute.creation_time | post.timestamp | |
| target.resource.attribute.labels[post_media_description] | post.media.description | |
| target.resource.attribute.labels[post_media_display_url] | post.media.display_url | |
| target.resource.attribute.labels[post_media_isSafe] | post.media.isSafe | |
| target.resource.attribute.labels[post_media_media_url] | post.media.media_url | |
| target.resource.attribute.labels[post_media_sizes_large_h] | post.media.sizes.large.h | |
| target.resource.attribute.labels[post_media_sizes_large_resize] | post.media.sizes.large.resize | |
| target.resource.attribute.labels[post_media_sizes_large_w] | post.media.sizes.large.w | |
| target.resource.attribute.labels[post_media_sizes_medium_h] | post.media.sizes.medium.h | |
| target.resource.attribute.labels[post_media_sizes_medium_resize] | post.media.sizes.medium.resize | |
| target.resource.attribute.labels[post_media_sizes_medium_w] | post.media.sizes.medium.w | |
| target.resource.attribute.labels[post_media_sizes_small_h] | post.media.sizes.small.h | |
| target.resource.attribute.labels[post_media_sizes_small_resize] | post.media.sizes.small.resize | |
| target.resource.attribute.labels[post_media_sizes_small_w] | post.media.sizes.small.w | |
| target.resource.attribute.labels[post_media_sizes_thumb_h] | post.media.sizes.thumb.h | |
| target.resource.attribute.labels[post_media_sizes_thumb_resize] | post.media.sizes.thumb.resize | |
| target.resource.attribute.labels[post_media_sizes_thumb_w] | post.media.sizes.thumb.w | |
| target.resource.attribute.labels[post_media_source] | post.media.source | |
| target.resource.attribute.labels[post_media_thumbnail] | post.media.thumbnail | |
| target.resource.attribute.labels[post_media_title] | post.media.title | |
| target.resource.attribute.labels[post_media_url] | post.media.url | |
| target.resource.attribute.labels[post_media_video_info_aspect_ratio] | post.media.video_info.aspect_ratio | |
| target.resource.attribute.labels[post_media_video_info_duration_millis] | post.media.video_info.duration_millis | |
| target.resource.attribute.labels[post_media_video_info_variants_bitrate] | post.media.video_info.variants.bitrate | |
| target.resource.attribute.labels[post_media_video_info_variants_content_type] | post.media.video_info.variants.content_type | |
| target.resource.attribute.labels[post_media_video_info_variants_url] | post.media.video_info.variants.url | |
| target.resource.resource_subtype | post.media.type | |
| target.url | source.link | |
| target.user.user_display_name | source.displayName | |
