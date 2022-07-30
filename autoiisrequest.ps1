param (
    [String]$hostname = "",
    [String]$location = "",
    [String]$site = "",
    [String]$template = "",
    [String]$ca_server ="",
    [switch]$force,
    [switch]$request,
    [switch]$install
)

[String[]] $help_text = @"
AutoIISRequest.ps1 [-hostname <Hostname>] [-location <Directory>] [-template <Template Name>] [-ca_server <CA Name>] [-request] [-install] [-force]
hostname: The hostname that should be present in the request. If this option is absent, the FQDN will be used.
location: A directory to save artifacts in (eg. requests inf, csr, crt). If this option is absent, `$HOME will be used.
site: Specify the site to install the certificate on. If you don't specify a site, and there is only one, the cert will be installed there. If there is more than one, the command will exit with an error.
template: Specify the certificate template to be used.
ca_server: The name of the CA Server to use. This only needs to be specified if the template can be issued from more than one CA. If this is the case, the script will provide the CA names.
request: Create a private key and submit a certificate request to the CA server.
install: Retrieve and install a certificate after the certificate is issued.
force: Overwrite artifact files if they exist.

NOTE: either "request" or "install" (but not both) must be specified on the commandline.
"@


# Function to initialize important variables prior to execution of the remainder of the script
function Set-Variables {

    #Dynamically construct a directory search root from the current environment
    $domain = $env:userdnsdomain.split(".") | ForEach-Object { -Join ("DC=", $_, ",") }
    $search_root = "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"
    foreach ($rdn in $domain) { $search_root = $search_root + $rdn }
    $search_root = $search_root.Substring(0,$search_root.Length-1)

    # CA Config string. Update this if the template will be issued from a different CA
    if ($ca_server -eq "") {
        $template_cas = @()
        $search = [ADSIsearcher]"(objectClass=pkienrollmentservice)"
        $search.SearchRoot = "$search_root"
        $results = $search.FindAll()
        foreach ($ca in $results) {
            if ($template -in $ca.properties.certificatetemplates) {
                $template_cas += $ca
            }
        }
        if ($template_cas.Count -gt 1) {
            Write-Output "The chosen template can be issued by more than one CA. Please provide the appropriate name on the command line using the -ca_server switch."
            Write-Output "Possible Issuers:"
            foreach ($ca in $template_cas) {
                Write-Output $ca.properties.displayname
            }
            Exit
        } elseif ($template_cas.Count -lt 1) {
            Write-Output "No CAs can issue the specified template"
            Exit
        } else {
            $ca_hostname=$template_cas[0].properties.dnshostname
            $ca_server = $template_cas[0].properties.displayname            
        }
    } else {
        $search = [ADSIsearcher]"(&(objectclass=pkienrollmentservice)(displayname=$ca_server))"
        $search.SearchRoot = "$search_root"
        $results = $search.findAll()
        $ca_hostname=$results[0].properties.dnshostname        
    }

    [String]$Script:caconfig = "$ca_hostname\$ca_server"
    

    # If the user does not specify a location for the inf file, use $HOME
    if ($Script:location -eq "") { 
        $Script:location = $HOME
    }

    [String] $Script:file = Join-Path -Path $Script:location -ChildPath "autoiisrequest"

    # If the user does not specify a site, and no sites are configured, bail with an error.
    # If the user does not specify a site, and only one site is defined, use it. 
    # IF the user does not specify a site, and there are multiple sites, bail with an error, and list the sites.
    # If the user specifies a site, confirm that it exists. If they mistyped, bail.
    if ($Script:site -eq "") {
        if ( (Get-IISSite).Length -lt 1 ) {
            Write-Output "No sites defined. At least one site must be defined for this script to execute."
            Exit
        } elseif ( (Get-IISSite).Length -gt 1 ) {
            Write-Output "More than one site defined. You must specify which site you want a certificate for using the -site commmand option"
            Write-Output "The following sites were identified:"
            (Get-IISSite).Name | Write-Output
            Exit
        } else {
            $Script:site = (Get-IISSite).Name
        }
    } else {
        if ( $Script:site -notin (Get-IISSite).Name ) {
            Write-Output "The specified site does not exist on this server. Check for typos."
            Write-Output "The following sites were identified:"
            (Get-IISSite).Name | Write-Output
            Exit
        } else {
            Write-Output "Site $Script:site exists. Continuing..."
        }
    }

    # If the administrator does not specify a hostname for the request, get the hostname from the web configuration if it exists.
    if ($Script:hostname -eq "") {
        $Script:hostname = ((Get-IISSiteBinding -Name $site -protocol "http").bindingInformation | Select-String -Pattern "(.+):\d+:(.*)").Matches.Groups[2].Value
    }

    # If the hostname is still empty, the IIS Site binding may not specify a hostname. We can assume the FQDN is okay.
    if ($Script:hostname -eq "") {
        [String] $Script:hostname = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName 
    }
}

#Function to clean up files created during issuance. Intended to be run if everything is successful.
function Remove-Tempfiles {
    param (
        [String]$file_location
    )

    Get-ChildItem $file_location autoiisrequest.* | Remove-Item
}

#Function to verify we are running on a machine with IIS installed
function Test-IIS {
    if ( (Get-WindowsFeature Web-Server).InstallState -ne "Installed" ) {
        Write-Output "IIS Not installed. IIS is required for this script to function."
        return $false
    } else {
        Write-Output "IIS is installed. Continuing..."
        return $true
    }
}

#
# If neither request nor install are specified, or if both request and installe are specified, bail.
#
if ( ($request -and $install) -or (!$request -and !$install) ) {
    Write-Output $help_text
    Exit

#
#Handle request process
#
} elseif ($request) {
    # Confirm we're running on an IIS Server. If not, Exit.
    if ( -not (Test-IIS) ) { Exit }

    # Call the "Set-Variables" function to populate all of the required variables
    Set-Variables

    #Check for existing requests
    if (Test-Path "$file.rid") {
        if ($force) {
            Write-Output "Previous request exists, but -force set. Will overwrite previous request"
        } else {
            Write-Output "The request ID file exists. Is there an outstanding request?"
            Write-Output "Use -install parameter to complete the request, or use the -force parameter to force overwrite."
            Exit            
        }
    }

    # Generate the private key and request
    Write-Output "Generating private key and certificate request and submitting to Certification Authority..."
    try {
        $enrollResult = Get-Certificate -Template $template -DnsName $hostname -SubjectName "CN=$hostname" -CertStoreLocation cert:\LocalMachine\My
    } catch {
        Write-Output "Error Requesting Certificate"
        Write-Output "$_"
        Exit
    }

    # Capture the request ID to a variable
    $request_id = $enrollResult.Request.Thumbprint

    if ($request_id -eq "") {
        Write-Output "Something went wrong. Request ID unavailable."
        Exit
    } else {
        # Write the request ID to a temporary file. We've already warned the user and exited if it exists and -force is not set.
        if (Test-Path "$file.rid") {
            if ($force) {
                Set-Content -Path "$file.rid" -Value $request_id
            } else {
                Write-Output "It shouldn't be possible to see this error"
                Exit
            }
        } else {
            Set-Content -Path "$file.rid" -Value $request_id
        }

    }



#
# Handle the Certificate Installation Process
#
} elseif ($install) {
    # Confirm we're running on an IIS Server. If not, Exit.
    if ( -not (Test-IIS) ) { Exit }

    # Call the "Set-Variables" function to populate all of the required variables
    Set-Variables

    # Obtain the request ID from the file where is was recorded during the request process
    if (Test-Path "$file.rid") {
        $request_id = Get-Content -Path "$file.rid"
    } else {
        Write-Output "Request ID file missing. Contact PKI adminstrators for assistance."
        Exit
    }

    # Get the request object corresponding to the request ID
    if (Test-Path "Cert:\LocalMachine\REQUEST\$request_id") {
        $request_obj = Get-ChildItem -Path "Cert:\LocalMachine\REQUEST\$request_id"
    } else {
        Write-Output "Certificate Request file missing. Contact PKI adminstrators for assistance."
    }

    # Retrive the Certificate
    try {
        $retrieve_result = Get-Certificate -Request $request_obj
    } catch {
        Write-Output "Error Retrieving Certificate"
        Write-Output "$_"
    }

    if ($retrieve_result.Status -eq "Issued") {
        $cert_thumbprint = $retrieve_result.Certificate.Thumbprint
        Write-Output "Certificate has been issued by the CA. Thumbprint: $cert_thumbprint"
    } elseif ($retrieve_result.Status -eq "Pending") {
        Write-Output "Certificate has not yet been issued by the CA. Contact the PKI Administrators for assistance."
        Exit
    } elseif ($retrieve_result.Status -eq "Denied") {
        Write-Output "Certificate request was Denied. Contact the PKI Administrators for assitance."
        #Cleanup request files
        Write-Output "Removing Temporary Files..."
        Remove-Tempfiles -file_location $location
        Exit
    } else {
        Write-Output "Something Else happened"
        Write-Output $retrieve_result
        Exit
    }

    # See if an https binding already exists
    if ( "https" -notin ((Get-IISSite $site).Bindings.protocol) ) {
        #If not, create the https binding for the site, based on the http binding information
        Write-Output "Creating https web Binding with new certificate..."
        $binding_ip = ((Get-IISSiteBinding -Name $site -protocol "http").bindingInformation | Select-String -Pattern "(.+):\d+:(.*)").Matches.Groups[1].Value
        $binding_host = ((Get-IISSiteBinding -Name $site -protocol "http").bindingInformation | Select-String -Pattern "(.+):\d+:(.*)").Matches.Groups[2].Value
        $binding_info = $binding_ip + ":443:" + $binding_host
        New-IISSiteBinding -Name "$site" -BindingInformation "$binding_info" -Protocol "https" -CertificateThumbPrint "$cert_thumbprint" -CertStoreLocation "Cert:\LocalMachine\My"
    } else {
        # If the binding exists, remove the binding (preserving the old certificates), and re-add it with the new certificate.
        $binding_info = (Get-IISSiteBinding -Name $site -protocol "https").bindingInformation
        Remove-IISSiteBinding -Name "$site" -Bindinginformation "$binding_info" -RemoveConfigOnly -protocol "https" -Confirm:$false
        Write-Output "Deleting Current Web Binding..."
        do {
            Start-Sleep -Seconds 1
        } until ( "https" -notin ((Get-IISSite $site).Bindings.protocol) )
        Write-Output "Creating Web Binding with new Certificate..."
        New-IISSiteBinding -Name "$site" -BindingInformation "$binding_info" -Protocol "https" -CertificateThumbPrint "$cert_thumbprint" -CertStoreLocation "Cert:\LocalMachine\My"
    }

    #Cleanup request files
    Write-Output "Removing Temporary Files..."
    Remove-Tempfiles -file_location $location

    
}