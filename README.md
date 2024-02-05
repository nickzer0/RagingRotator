[![Go Report Card](https://goreportcard.com/badge/github.com/nickzer0/RagingRotator)](https://goreportcard.com/report/github.com/nickzer0/RagingRotator)

# RagingRotator
A tool for carrying out brute force attacks against Office 365, with built in IP rotation use AWS gateways.

Sends login requests to `https://login.microsoftonline.com/rst2.srf` which returns error codes based on the status of the account. These error codes are documented [here](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes#aadsts-error-codes).

# Usage
```
  -h            Print help information
  -user         Username for authentication
  -userfile     Path to a file containing a list of usernames
  -domain       Domain for authentication
  -pass         Password for authentication
  -passfile     Path to a file containing a list of passwords
  -userpassfile Path to a file containing a list of username:password pairs
  -delay        Delay between requests in seconds (default: 1)
  -output       Path to the output file for results
  -accesskey    AWS access key for API Gateway deployment
  -secretkey    AWS secret key for API Gateway deployment
  -cleanup		Cleans up unused AWS API Gateways, loops until complete
```
