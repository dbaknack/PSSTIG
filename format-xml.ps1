$RawXML = Get-Content -path ".\sources\U_MS_SQL_Server_2016_Database_V2R7_Manual_STIG\U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf.xml" -raw
$RawXML `
    -replace '><',">`n<" `
    -replace'<check-content>',"<check-content>`n" `
    -replace '</check-content>',"</check-content>" `
    -replace '(<fixtext fixref=.*>)',('$1{0}' -f "`n") `
    -replace '(</fixtext>)',('{0}$1' -f "`n") `
    -replace '&gt;',"&gt;`n" `
    -replace '&lt;VulnDiscussion&gt;',"&lt;VulnDiscussion&gt;" `
    -replace '&lt;/VulnDiscussion&gt;',"&lt;/VulnDiscussion&gt;" | out-file '.\database_xml.xml' 

$xmlPath = "./database_xml.xml"
[xml]$xmlContent = Get-Content -Path $xmlPath


$Group = @()
$Group += $xmlContent.Benchmark.Group | ForEach-Object {
    [pscustomobject]@{
        CP_PrimaryKey = ($_.id) -replace ("V-",'')
        ID = $_.id
        Title = $_.title
        Description = $_.description
        Rule = $_.rule
    }
}

$Rule = @()
$Rule += $xmlContent.Benchmark.Group.Rule | ForEach-Object {
    [pscustomobject]@{
        CP_PrimaryKey = ($_.id) -replace ("V-",'')
        ID = $_.id
        Weight = $_.weight
        Severity = $_.severity
        Version = $_.version
        Title = $_.title
        Description = $_.description
        Reference = $_.reference
        Ident = $_.ident
        FixText = $_.fixtext
        Check = $_.check
    }
}

$TagTable = [ordered]@{
    VulnDiscussion = @{pattern = '(<VulnDiscussion>)(.*)(</VulnDiscussion>)'}
    FalsePositives = @{pattern = '(<FalsePositives>)(.*)(</FalsePositives>)'}
    FalseNegatives = @{pattern = '(<FalseNegatives>)(.*)(</FalseNegatives>)'}
    Documentable = @{pattern = '(<Documentable>)(.*)(</Documentable>)'}
    Mitigations = @{pattern = '(<Mitigations>)(.*)(</Mitigations>)'}
    SeverityOverrideGuidance = @{pattern = '(<SeverityOverrideGuidance>)(.*)(</SeverityOverrideGuidance>)'}
    PotentialImpacts = @{pattern = '(<PotentialImpacts>)(.*)(</PotentialImpacts>)'}
    ThirdPartyTools = @{pattern = '(<ThirdPartyTools>)(.*)(</ThirdPartyTools>)'}
    MitigationControl = @{pattern = '(<MitigationControl>)(.*)(</MitigationControl>)'}
    Responsibility = @{pattern = '(<Responsibility>)(.*)(</Responsibility>)'}
    IAControls = @{pattern = '(<IAControls>)(.*)(</IAControls>)'}
}


$Rule | ForEach-Object{
    $DescriptionList = @()
    ($_.Description) -split (" ") | ForEach-Object{
        $DescriptionList += $_ -replace ("\n","")
    }

    $DescriptionString = $DescriptionList -join " "
    $DescriptionTable = [ordered]@{}
    foreach($tag in $TagTable.Keys){
        if($DescriptionString -match $TagTable.$tag.pattern){
            $DescriptionTable.Add($tag,$Matches[2])
        }
    }
    $Description = New-Object PSObject -Property $DescriptionTable
    $_ | Add-Member -MemberType NoteProperty -Name "New_Description" -Value $Description
}


$Check = @()
$Check += $xmlContent.Benchmark.Group.Rule.Check | ForEach-Object {
    [pscustomobject]@{
        System = $_.system
        CheckContentRef = $_.'check-content-ref'
        CheckContent = $_.'check-content'
    }
}


foreach($cc in $Check){
    $New_CheckContent = @()
    ($cc.CheckContent -split ("`n")) | ForEach-Object{
        if($_.length -ne 0){
            $New_CheckContent += $_
        }
    }
    $cc.CheckContent = $New_CheckContent
}