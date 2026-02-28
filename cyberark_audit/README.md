* Access google storage container

* Time assignment:
    * FROM = TO (read from the blob)
    * TO   = CURRENT TIME

* Auth/Authn to the CyberArk Identity API Endpoint (CyberArk SDK)

* Build the query body in JSON
    * Identity Logs
    * Conjur Logs
    * Privilege Cloud Logs

* Retrieve a cursorRef from the Audit API (requests)

* Retrieve the payload via the cursorRef (requests)

* Run the ingestion function to send payload to Chronicle

* Validate successful payload reception into Chronicle (HTTP 200)

* Update the blob with the FROM and TO that was set at the beginning of the run (only if successful)

* De-Auth



IMPORTS:

* from google.cloud
    * import storage
* from common
    * from common import env_constants
    * from common import ingest
    * from common import utils
* import datetime
* import json
* import time
