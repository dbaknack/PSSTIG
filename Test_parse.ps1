$xmlContent = Get-Content -Path .\Sources\U_MS_SQL_Server_2016_Instance_V2R10_Manual_STIG\U_MS_SQL_Server_2016_Instance_STIG_V2R10_Manual-xccdf.xml



# Load the XML document
$xmlDocument = [xml]$xmlContent

# Define XML namespace
$namespace = New-Object System.Xml.XmlNamespaceManager($xmlDocument.NameTable)
$namespace.AddNamespace("ns", "http://checklists.nist.gov/xccdf/1.1")

# Extract information about profiles
$profiles = $xmlDocument.SelectNodes("//ns:Profile", $namespace) | ForEach-Object {
    $profileId = $_.GetAttribute("id")
    $profileTitle = $_.SelectSingleNode("ns:title", $namespace).InnerText
    $profileDescription = $_.SelectSingleNode("ns:description", $namespace).InnerText

    # Process other profile information as needed

    [PSCustomObject]@{
        ProfileId = $profileId
        Title = $profileTitle
        Description = $profileDescription
    }
}

# Extract information about rules
$rules = $xmlDocument.SelectNodes("//ns:Rule", $namespace) | ForEach-Object {
    $ruleId = $_.GetAttribute("id")
    $ruleTitle = $_.SelectSingleNode("ns:title", $namespace).InnerText
    $ruleDescription = $_.SelectSingleNode("ns:description", $namespace).InnerText

    # Process other rule information as needed

    [PSCustomObject]@{
        RuleId = $ruleId
        Title = $ruleTitle
        Description = $ruleDescription
    }
}


$rules  # RuleID, Title, and Description
$rules.Description[0]


# Load the XML document
$xmlDocument = [xml]$xmlContent

# Define XML namespace
$namespace = New-Object System.Xml.XmlNamespaceManager($xmlDocument.NameTable)
$namespace.AddNamespace("ns", "http://checklists.nist.gov/xccdf/1.1")

# Extract information about rules
$rules = $xmlDocument.SelectNodes("//ns:Rule", $namespace) | ForEach-Object {
    $ruleId = $_.GetAttribute("id")
    $ruleTitle = $_.SelectSingleNode("ns:title", $namespace).InnerText
    $ruleDescription = $_.SelectSingleNode("ns:description", $namespace).InnerText

    # Extract VulnDiscussion from description
    $vulnDiscussion = [regex]::Match($ruleDescription, '<VulnDiscussion>(.*?)</VulnDiscussion>').Groups[1].Value

    # Process other rule information as needed

    [PSCustomObject]@{
        RuleId = $ruleId
        Title = $ruleTitle
        VulnDiscussion = $vulnDiscussion
    }
}

$rules.VulnDiscussion[4]
