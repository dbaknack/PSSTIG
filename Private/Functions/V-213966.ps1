# Check SQL Server Configuration for password encryption
param (
    [string]$instanceName
)

# Initialize hashtable for results
$results = @{
    "ComplianceStatus" = 1  # Default to compliant (1)
    "Comments" = @()  # Array to store comments
}

try {
    # Check if Force Encryption is set to "NO"
    $forceEncryptionPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($instanceName)\MSSQLServer\SuperSocketNetLib\ForceEncryption"
    $forceEncryption = (Get-ItemProperty -Path $forceEncryptionPath -ErrorAction Stop).ForceEncryption

    if ($forceEncryption -eq 0) {
        $results["ComplianceStatus"] = 0  # Set to non-compliant (0)
        $results["Comments"] += "Force Encryption is set to 'NO'. This is a finding."
    }

    # Check the certificate on the "Certificate" tab
    $certificatePath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($instanceName)\MSSQLServer\SuperSocketNetLib\Certificate"
    $certificateThumbprint = (Get-ItemProperty -Path $certificatePath -ErrorAction Stop).Thumbprint

    # Check if the certificate is not a DoD-approved certificate or not listed
    $certificate = Get-Item -LiteralPath "Cert:\LocalMachine\My\$($certificateThumbprint)"
    if (-not $certificate -or -not $certificate.Issuer -match "DoD") {
        $results["ComplianceStatus"] = 0  # Set to non-compliant (0)
        $results["Comments"] += "Certificate is not a DoD-approved certificate or not listed. This is a finding."
    }

    # For clustered instances, the Certificate will NOT be shown in SQL Server Configuration Manager.
    # Check the certificate in the certificate store
    $certificateStorePath = "Cert:\LocalMachine\My"
    $certificates = Get-ChildItem -Path $certificateStorePath

    foreach ($cert in $certificates) {
        if ($cert.Thumbprint -eq $certificateThumbprint -and -not $cert.Issuer -match "DoD") {
            $results["ComplianceStatus"] = 0  # Set to non-compliant (0)
            $results["Comments"] += "Certificate in certificate store is not a DoD-approved certificate. This is a finding."
        }
    }
} catch {
    # Handle exceptions and add comments to results
    $results["ComplianceStatus"] = 0  # Set to non-compliant (0)
    $results["Comments"] += "An error occurred: $_"
}

# Output the final results
$results
