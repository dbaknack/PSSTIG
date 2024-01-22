$enclave    = 'NIPERNET'

write-host "Running Audit on instance '$($instance.instance_name) on $enclave'..." -ForegroundColor Yellow
write-host "----------------------------------------------" -ForegroundColor Yellow

$check_counter = 1
$audit_results = @{}
# [server_level checks ] ----------------------------------------------------------------- #
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214042'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $server_name = ([string](Get-SqlInstances).Keys)
    $results     = Run-Finding214042 -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($server_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($server_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214032'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214032  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

# [Instance_level checks] ---------------------------------------------------------------- #
$instance_names =  @()
foreach($host_name in (Get-SqlInstances).keys){
    $instance_names += (Get-SqlInstances).$host_name
}


foreach($instance in $instance_names){

    # ------------------------------------------------------------------------------- 214045
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214045'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214045 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1
        write-host "$($instance.instance_name)" -ForegroundColor Yellow

    # ------------------------------------------------------------------------------- 214044
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214044' for ..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214044 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214043
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214043'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214043 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214041
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214041'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214041 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214040
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214040'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214040 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214039
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214039'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214039 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214038
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214038'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214038 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214037
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214037'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214037 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214036
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214036'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214036 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214035
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214035'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214035 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214034
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214034'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214034 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214033
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214033'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214033 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214031
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214031'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214031 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214030
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214030'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214030 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214029
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214029'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214029 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

      # ------------------------------------------------------------------------------- 214028
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214028'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214028 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1
    # ------------------------------------------------------------------------------- 214027
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214027'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214027 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214026
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214026'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214026 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214025
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214025'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214025 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214024
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214024'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214024 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214023
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214023'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214023 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1


    # ------------------------------------------------------------------------------- 214021
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214021'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214021 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1


  # ------------------------------------------------------------------------------- 214020
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214020'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214020 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 213934
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-213934'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding213934 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1


    # ------------------------------------------------------------------------------- 213932
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-213932'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding213932 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214018
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214018'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214018 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1
    # ------------------------------------------------------------------------------- 214017
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214017'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214017 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214016
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214016'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214016 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1

    # ------------------------------------------------------------------------------- 214015
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214015'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214015 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1
    # -------------- results returned here -------------- #

    # ------------------------------------------------------------------------------- 214014
    write-host " ( $check_counter ) - Evaluating compliance of finding 'V-214014'..." -ForegroundColor Cyan
    write-host "----------------------------------------------" -ForegroundColor Cyan
    $results = Run-Finding214014 -InstanceName $instance.instance_name  -enclave $enclave
    Write-host "- Finding description: $($results.check_description)" -ForegroundColor Cyan
    Write-host "- Finding Cat Lvl:     $($results.cat)" -ForegroundColor Cyan
    if($($results.check_results) -eq 'not_a_finding'){
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Green
    }else{
        Write-host "- Finding status:      $($results.check_results)`n" -ForegroundColor Red
    }
    $audit_results.Add("$($instance.instance_name)$([string]$results.finding_id)",@{})
    $audit_results.("$($instance.instance_name)$([string]$results.finding_id)") = $results
    $check_counter = $check_counter + 1
    # -------------- results returned here -------------- #
    $out_put = @()
    foreach($audit_item in $audit_results.Keys){
    $out_put += $audit_results.$audit_item.csv_formatted | Select-Object -Skip 1
    }
    $out_put | clip.exe

    #read-host -Prompt 'continue'
    #$audit_results = @{}
}
$coalated_results = @()
foreach($host_inst in $audit_results.Keys){
    $results_table_2 = @{
        host_name_instance_name = $host_inst
        finding_id              = $audit_results.$host_inst.finding_id
        cat                     = $audit_results.$host_inst.cat
        status                  = $audit_results.$host_inst.check_results
    }

 $coalated_results += ConvertFrom-Hashtable $results_table_2
}