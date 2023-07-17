# Python Integrator SDK

> What is the HCX SDK?

HCX SDK is a bridge/switch between provider and payor, it validates request from provider to payor & allows payor to respond back to the provider.

> Steps

1. Initialzation of the SDK: Initilaize the `HCXIntegrator` class
2. Outgoing Requests: There are two types of outgoing requests
```mermaid
graph TD;
    A-->B;
    A-->C;
    B-->D;
    C-->D;
```

## Initiating the SDK
Python class: `HCXIntegrator()`

Member Variables:
```py
config: dict {
    'participantCode': "",
    'authBasePath': “”,  # will give you token
    'protocolBasePath': “”,
    'username': “”,
    'password': “”,
    'encryptionPrivateKey': “”
    'igUrl': “”,
    'participantCode': “”
}
```

## Outgoing Methods
As a sender, the steps are following:

### Validating FHIR request

```py
def validatePayload(jwePayload : str, operation: Operation, error: dict):
    returns bool
```
Handles errors as per: [hcx-protocol | error-descriptions](https://docs.hcxprotocol.io/hcx-technical-specifications/open-protocol/key-components-building-blocks/error-descriptions) while excluding the following error messages:
`ERR_INVALID_ENCRYPTION`,
`ERR_WRONG_DOMAIN_PAYLOAD`,
`ERR_INVALID_DOMAIN_PAYLOAD`,
`ERR_SERVICE_UNAVAILABLE`,
`ERR_DOMAIN_PROCESSING`.

### Create a Header for the payload
```py
def create_headers(senderCode: str, recipientCode: str,
                   apiCallId: str, correlationId: str,
                   actionJwe: str, onActionStatus: str,
                   headers: dict, error: dict):
    return Json
```
* Creates header. Only the recipient code needs to be provided. Rest parameters are set on the creation of the HCXIntegrator instance.
* It returns a JSON object (header).
* For creating action headers JWE payload received for the action call should be provided

### Encrypt Payload
```py
def encrypt_payload(headers: dict, fhirpayload: str):
    # find public certificate from the searchRegistry method
    # encrypt payload using public certificate
    # Returns a JWE (json) object with encrypted fields
    return JWE
```

### Search Registry
```py
def searchRegistry(searchField: str, searchValue: str):
    # Creates HCX token
    # Create search payload, example: 
    # {"filters": {
    #   searchField: {
    #       "eq": searchValue
    #   }
    # }}
    # Returns Json object with registry fields in it.
    return Json
```

### Initialize HCX Call

```py
def initializeHCXCall(jewPayload: str, operation: Operation):
    return response
```

This function does the following:
* Generate the token using the config (generateHCXToken function) and adds to the call.
* Call the HCX  API
* Recieved response will be added to response as `{“responseObj”: {success/error response}}`

### Wrapper classes
1. For action API request: 
```py
def generate(fhirPayload, operation, recipientCode):
    return output
```
* output is of type `dict`. It can be of wither of the following cases:
    1. On Success: success output- 
    ```json
    {
        "payload":{}, -  jwe payload
        "responseObj": {
         "timestamp": , - unix timestamp
         "correlation_id": "", - fetched from incoming request
         "api_call_id": "" - fetched from incoming request
        }
    }
    ```
    2. error output-
    ```json
    {
        "payload":{}, -  jwe payload
        "responseObj":{
         "timestamp": , - unix timestamp
         "error": {
           "code" : "", - error code
           "message": "", - error message
           "trace":"" - error trace
         }
       }
    }
    ```



## Incoming Methods

### Protocol Validations
```py
def validateRequest(jwePayload: str, operations: Operation, error: dict):
    returns bool
```
Validation happens against the Recipient error scenarios as per: https://docs.hcxprotocol.io/hcx-technical-specifications/open-protocol/key-components-building-blocks/error-descriptions

Excluded error scenarios
`ERR_INVALID_ENCRYPTION`,`ERR_WRONG_DOMAIN_PAYLOAD`,`ERR_INVALID_DOMAIN_PAYLOAD`,`ERR_SERVICE_UNAVAILABLE`,`ERR_DOMAIN_PROCESSING`.

### Decrypt Payload

```py
def decryptPayload(encryptedString: str):
    # Finds the private key, decrypts the encrypted JWE.
    #
    # If successful - returns a dictionary that contains header & FHIR object
    # Example: 
    # {
	#   “headers”: {},   # protocol headers
	#   “fhirPayload”: {}  # FHIR object
    # }
    # 
    # If Failed - returns a dictionary containing error codes & messages
    # Example:
    # {
    # 	“error_code”: “error_mesage”
    # }
    return dict
```

### Domain object Validation
``` py
def validatePayload(fhirPayload: str, operation: Operation, error: dict)
```
**NOTE**
* Same function as that of Outgoing requests
* fhirPayload parameter should be the str received from the decryptPayload function.
Returns:
```py
True: # If the payload passes all the checks and an empty error output for successful operation.
False: # If the payload fails validations and error output as per the recipient error scenarios.
```
Following return scenarios to be returned:
`ERR_WRONG_DOMAIN_PAYLOAD`,
`ERR_INVALID_DOMAIN_PAYLOAD` - Along with the FHIR validation results.


### Acknowledgment
```py
def sendResponse(error: dict, output: dict):
    # If the error is empty, success response is to be returned.
    # Example:
    # {
    #   "headers":{}, - protocol headers
    #   "fhirPayload":{}, - fhir object
    #   "responseObj": {
    #   "timestamp": , - unix timestamp
    #   "correlation_id": "", - fetched from incoming request
    #   "api_call_id": "" - fetched from incoming request
    # }

    # If there are any errors, an error response object is returned.
    # Example:
    # {   
    #   "headers":{}, - protocol headers
    #   "fhirPayload":{}, - fhir object
    #   "responseObj":{
    #   "timestamp": , - unix timestamp
    #   "error": {
    #        "code" : "", - error code
    #        "message": "", - error message
    #        "trace":"" - error trace
    #     }
    #   }

    return dict
}
```
### The process

```py
def process(jwePayload: str, operation: Operation):
    return dict
```

* Returns output (dict) that contains `fhirPayload`, `headers`, `responseObj (success/error response to be sent to hcx gateway)`
* Functions calls happen in the following order:
    1. validateRequest
    2. decryptPayload
    3. validatePayload
    4. sendResponse



## Operations

Operations contains the redirect URL for a specific API calls.
```py
class HcxOperations():
        COVERAGE_ELIGIBILITY_CHECK ="/coverageeligibility/check"
        COVERAGE_ELIGIBILITY_ON_CHECK = "/coverageeligibility/on_check"
        PRE_AUTH_SUBMIT = "/preauth/submit"
        PRE_AUTH_ON_SUBMIT = "/preauth/on_submit"
        CLAIM_SUBMIT = "/claim/submit"
        CLAIM_ON_SUBMIT = "/claim/on_submit"
        PAYMENT_NOTICE_REQUEST = "/paymentnotice/request"
        PAYMENT_NOTICE_ON_REQUEST = "/paymentnotice/on_request"
        HCX_STATUS = "/hcx/status"
        HCX_ON_STATUS = "/hcx/on_status"
        COMMUNICATION_REQUEST = "/communication/request"
        COMMUNICATION_ON_REQUEST = "/communication/on_request"
        PREDETERMINATION_SUBMIT = "/predetermination/submit"
        PREDETERMINATION_ON_SUBMIT = "/predetermination/on_submit"
```




