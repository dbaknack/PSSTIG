[xml]$xmlContent = Get-Content -path ".\Sources\U_MS_SQL_Server_2016_Database_V2R7_Manual_STIG\U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf.xml" #-Raw
$ParsingTable = [ordered]@{
    Remove_Blank_Lines = @{
        Match = '^\s*$'
        ReplaceWith = ''
    }
}

$ParsedStep1 = $RawData -replace ($ParsingTable.Remove_Blank_Lines.Match,$ParsingTable.Remove_Blank_Lines.ReplaceWith)
Set-Content -path ".\Sources\U_MS_SQL_Server_2016_Database_V2R7_Manual_STIG\U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf.xml" -Value $ParsedStep1


# Your XML content here
$xmlContent = @"
<!-- Paste the XML content here -->
"@

# Load the XML document
$xmlDocument = [xml]$xmlContent
$xmlDocument.Benchmark.Group.Rule.fixtext."#text"[0]
# Define XML namespace
$namespace = New-Object System.Xml.XmlNamespaceManager($xmlDocument.NameTable)
$namespace.AddNamespace("ns", "http://checklists.nist.gov/xccdf/1.1")
$xmlDocument.SelectNodes("//ns:Profile", $namespace)

# Extract information about profiles
$profiles = $xmlDocument.SelectNodes("//ns:Profile", $namespace) | ForEach-Object {
    $profileId = $_.GetAttribute("id")
    $profileTitle = $_.SelectSingleNode("ns:title", $namespace).InnerText
    $profileDescription = $_.SelectSingleNode("ns:description", $namespace).InnerText}

    # Extract VulnDiscussion from description
    $vulnDiscussion = [regex]::Match($profileDescription, '<VulnDiscussion>(.*?)</VulnDiscussion>').Groups[1].Value

    # Process other profile information as needed

    [PSCustomObject]@{
        ProfileId = $profileId
        Title = $profileTitle
        VulnDiscussion = $vulnDiscussion
    }
}

# Print the results
$profiles | Format-Table
