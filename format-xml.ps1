$RawXML = Get-Content -path ".\sources\U_MS_SQL_Server_2016_Database_V2R7_Manual_STIG\U_MS_SQL_Server_2016_Database_STIG_V2R7_Manual-xccdf.xml" -raw
$RawXML `
    -replace '><',">`n<" `
    -replace'<check-content>',"<check-content>`n" `
    -replace '</check-content>',"`n</check-content>" `
    -replace '(<fixtext fixref=.*>)',('$1{0}' -f "`n") `
    -replace '(</fixtext>)',('{0}$1' -f "`n") `
    -replace '&gt;',"&gt;`n" `
    -replace '&lt;VulnDiscussion&gt;',"`n&lt;VulnDiscussion&gt;" `
    -replace '&lt;/VulnDiscussion&gt;',"`n&lt;/VulnDiscussion&gt;" | out-file '.\database_xml.xml' 