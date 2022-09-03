# autoiisrequest

This utility allows IIS administrators to request certificates from an ADCS instance. It is designed to hide the complexity of the interactions with the  
CA by making intelligent guesses about required request parameters.

AutoIISRequest.ps1 [optional parameters] [-request | -install] [-force]
Mandatory Parameters:
* request: Create a private key and submit a certificate request to the CA server.
* install: Retrieve and install a certificate after the certificate is issued.
NOTE: either "request" or "install" (but not both) must be specified on the commandline. All other parameters are optional

Optional Parameters:
* hostname: The hostname that should be present in the request. If this option is absent, the FQDN will be used.
* location: A directory to save artifacts in (eg. requests inf, csr, crt). If this option is absent, `$HOME will be used.
* site: Specify the site to install the certificate on. If you don't specify a site, and there is only one, the cert will be installed there. If there is more than one, the command will exit with an error.
* template: Specify the certificate template to be used.
* ca_server: The name of the CA Server to use. This only needs to be specified if the template can be issued from more than one CA. If this is the case, the script will provide the CA names.
* force: Overwrite artifact files if they exist.
