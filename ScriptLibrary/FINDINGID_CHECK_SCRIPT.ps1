$timer = [System.Diagnostics.Stopwatch]::StartNew()
$CheckResultsTable = @{
    host_name            = ''
    finding_id           = '214042'
    check_description    = "The SQL Server Browser service must be disabled unless specifically required and approved"
    check_duration_milli = ''
    check_completed      = [bool]
    check_results        = [psobject]
}

try{
    $CheckResultsTable.host_name        = [System.Net.Dns]::GetHostName()
    $CheckResultsTable.check_completed  = $true 
    $CheckResultsTable.check_results    = Get-Service -Name "SQLBrowser" -ErrorAction Stop
   
}catch{
    $CheckResultsTable.check_completed  = $false
    $CheckResultsTable.check_results    = $Error[0]
}

$elapsed_time = $timer.ElapsedMilliseconds
$timer.stop()
$CheckResultsTable.check_duration_milli = $elapsed_time

$CheckResultsTable