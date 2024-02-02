# 1.0 -     set erroractionpreference to stop, and import required modules
$ErrorActionPreference = 'STOP'
Import-Module C:\LocalRepo\PSUTILITIES\PSUTILITIES.psd1
Import-Module .\PSSTIG.psd1 


$PSSTIGVIEWER = PSSTIGVIEWER
$PSSTIGVIEWER.Initalize(@{ExePath = "C:\Users\alexhernandez\Documents\Software\STIG_VIEWER_64_3_2_0\STIG Viewer 3.exe"})
$PSSTIGVIEWER.StartStigViewer()
$PSSTIGVIEWER.StopStigViewer()
$PSSTIGVIEWER.RestartStigViewer()

$PSSTIGMANUAL = PSSTIGMANUAL
$PSSTIGMANUAL.DownloadManual(@{
    LinkLabel           = "MSSQL_Server_2016"
    SaveToFolderPath    = ".\test2"
})

# 1.1 -   runs the set up when first using tool
$PSSTIG = PSSTIG

$PSSTIG.Initalize(@{
    ParentFolderPath    = '.\Data'
    DataSource          = 'SQLServerInstance'
})



# 2.0 -   define credentials to be used
$myCreds = Get-Credential

# 3.0 -   create sessions to remote hosts
$PSSTIG.CreateSessions(@{
    All         = $true
    HostList    = @()
    Creds       = $myCreds
    usinPort    = 40482
})



# 4.0 -   define levels
$InstanceLevelParams = $PSSTIG.MyHostDataSet(@{
    DataSource  = "SQLServerInstance"
    Level       = "Instance"
})

# 5.0 -   perform checks
#----------------------------------------------------------------------------------------#
# Finding:V-213988
$findingID = 'V-213988'

$Session = New-PSSession -ComputerName "VIPTO-PowerShell" -Port 40482 -Credential $myCreds

$CheckListName = "VIPTO-POWERSHELL_SANDBOX01_SQLServerInstance"
Get-TargetData -Session $Session -CheckListName $CheckListName
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams  = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        SourceDataFrom  = $PSSTIG.Configuration.Files.ServerAdminAccountsList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        CheckListType   = $InstanceLevelParam.CheckListType
        DisplayStatus   = $true
    }
    Invoke-Finding213988  @FunctionParams
}

#----------------------------------------------------------------------------------------#
# Finding:V-213987
$findingID = 'V-213987'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Run-Finding213987 @FunctionParams
}



# use this to get sql instance names
# funding 1
Function Run-Finding214042{
      param(
          $enclave
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214042'
      $remediate_file_name       = 'Remediate-SQLBrowserService.md'
      $check_description         = 'The SQL Server Browser service must be disabled unless specifically required and approved'
      $cat_level                 = '3'
      #----------------#
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = ([string](Get-SqlInstances).Keys)
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = Get-Service -Name "SQLBrowser" -ErrorAction Stop
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
 
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.status){
              'Running' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $check_description. Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              'Stopped' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $check_description. Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
$myCreds = Get-Credential
Enter-PSSession -ComputerName "VIPTO-POWERSHELL"-Credential $myCreds -Port 40482


# funding 2
Function Run-Finding214045{
    param([string]$InstanceName,[string]$enclave)

  $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
  $finding_id                = 'V-214045'
  $remediate_file_name       = 'Remediate-SQL-Authentication_Method.md'
  $check_description         = 'When using command-line tools such as SQLCMD in a mixed-mode authentication environment, users must use a logon method that does not expose the password.'
  $cat_level                 = '1'

  # check to see uwhat if any script will be ran
  $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
  if($scripts_to_rn -eq 0){
      $no_checks_run_scripts = $true
  }else{
      $no_checks_run_scripts = $false
  }

  # only when there is scripts to run do we care to do this step
  $checks_list = @()
  $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
  $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script


  if($no_checks_run_scripts -eq $false){
    switch($check_type){
        'sql_instance_check'{
        $checks_list += 'sql_instance_check'
            $is_sql_instance_check = $true
            $Query_Params = @{
                instance_name   = $InstanceName
                database_name   = 'master'
                query           = $check_todo
            }
        }
    }
  }


  $check_results_table = @{}
  # here we do the checks that will query a database
  if($is_sql_instance_check){
      [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
      $check_results_table.Add('sql_instance_check',$sql_query_result)
  }


  # the results are evaluated by the type of check, the exections are evaluated
  $my_considerations = @{
      remarks = 'mixed mode is not used'
  }
  if($check_results_table[$checks_list[0]].check_result  -eq 1){
    $status = 1
  }else{
    $status = 0
  }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }


      switch($status){
            {$_ -eq 0} {
                $CheckResultsTable.check_results = 'Open'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
            {$_ -eq 1} {
                $CheckResultsTable.check_results = 'not_a_finding'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
        }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 3
Function Run-Finding214044{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214044'
      $remediate_file_name       = 'Remediate-SQLIsClustered_Setting.md'
      $check_description         = "If the SQL Server Browser Service is specifically required and approved, SQL instances must be hidden"
      $cat_level                 = '3'
      #----------------#
 
      # by default, we use master for instance level checks
      $databaseName = 'master'
      $TsqlCommand = "
      declare @HiddenInstance int
      SELECT CASE
      WHEN @HiddenInstance = 0
      AND Serverproperty('IsClustered') = 0 THEN 'No'
      ELSE 'Yes'
      END AS [Hidden]"
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = "If the SQL Server Browser Service is specifically required and approved, SQL instances must be hidden"
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.host_name        = [System.Net.Dns]::GetHostName()
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
 
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.hidden){
              'No' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              'Yes' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 4
Function Run-Finding214043{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214043'
      $remediate_file_name       = 'Remediate-Replication_Xps.md'
      $check_description         = "SQL Server Replication Xps feature must be disabled, unless specifically required and approved"
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
          EXEC SP_CONFIGURE 'show advanced options', '1';
          RECONFIGURE WITH OVERRIDE;
          EXEC SP_CONFIGURE 'replication xps'"
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.host_name        = [System.Net.Dns]::GetHostName()
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 5
Function Run-Finding214041{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214041'
      $remediate_file_name       = 'Remediate-External_Script.md'
      $check_description         = "SQL Server External Scripts Enabled feature must be disabled, unless specifically required and approved."
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      EXEC SP_CONFIGURE 'show advanced options', '1';
      RECONFIGURE WITH OVERRIDE;
      EXEC SP_CONFIGURE 'external scripts enabled'; "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 6
Function Run-Finding214040{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214040'
      $remediate_file_name       = 'Remediate-Remote_Data_Archivest.md'
      $check_description         = "Remote Data Archive feature must be disabled, unless specifically required and approved."
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      EXEC SP_CONFIGURE 'show advanced options', '1';
      RECONFIGURE WITH OVERRIDE;
      EXEC SP_CONFIGURE 'remote data archive'; "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 7
Function Run-Finding214039{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214039'
      $remediate_file_name       = 'Remdiate-Allow_Polybase_Export.md'
      $check_description         = "Allow Polybase Export feature must be disabled, unless specifically required and approved."
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      EXEC SP_CONFIGURE 'show advanced options', '1';
      RECONFIGURE WITH OVERRIDE;
      EXEC SP_CONFIGURE 'allow polybase export';  "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 8
Function Run-Finding214038{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214038'
      $remediate_file_name       = 'Remediate-Hadoop_Connectivity.md'
      $check_description         = "Hadoop Connectivity feature must be disabled, unless specifically required and approved."
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      EXEC SP_CONFIGURE 'show advanced options', '1';
      RECONFIGURE WITH OVERRIDE;
      EXEC SP_CONFIGURE 'hadoop connectivity';  "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 9
Function Run-Finding214037{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214037'
      $remediate_file_name       = 'Remediate-Remote_Access.md'
      $check_description         = 'Remote Access feature must be disabled, unless specifically required and approved.'
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      EXEC SP_CONFIGURE 'show advanced options', '1';
      RECONFIGURE WITH OVERRIDE;
      EXEC SP_CONFIGURE 'remote access'; "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave             = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted       = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 10
Function Run-Finding214036{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214036'
      $remediate_file_name       = 'Remediate-User_Options.md'
      $check_description         = 'SQL Server User Options feature must be disabled, unless specifically required and approved.'
      $cat_level                 = '2'
      #----------------#
 
 
      $databaseName = 'master'
      $TsqlCommand = "
          EXEC SP_CONFIGURE 'show advanced options', '1';
          RECONFIGURE WITH OVERRIDE;
          EXEC SP_CONFIGURE 'user options'; "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 11
Function Run-Finding214035{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214035'
      $remediate_file_name       = 'Remediate-Ole_Automation_Procedures.md'
      $check_description         = 'Ole Automation Procedures feature must be disabled, unless specifically required and approved.'
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      EXEC SP_CONFIGURE 'show advanced options', '1';
      RECONFIGURE WITH OVERRIDE;
      EXEC SP_CONFIGURE 'Ole Automation Procedures'; "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 12
Function Run-Finding214034{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214034'
      $remediate_file_name       = 'Remediate-Filestream.md'
      $check_description         = 'Filestream must be disabled, unless specifically required and approved.'
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      EXEC sp_configure 'filestream access level' "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.config_value){
              '1' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 13
Function Run-Finding214033{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214033'
      $remediate_file_name       = 'Remediate-Access_Registry.md'
      $check_description         = 'SQL Server execute permissions to access the registry must be revoked, unless specifically required and approved.'
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
          ;WITH cte_temp AS (
            SELECT
              OBJECT_NAME(major_id) AS [Stored Procedure]
              ,dpr.NAME AS [Principal]
            FROM sys.database_permissions AS dp
            INNER JOIN sys.database_principals AS dpr ON dp.grantee_principal_id = dpr.principal_id
            WHERE major_id IN (
              OBJECT_ID('xp_regaddmultistring')
              ,OBJECT_ID('xp_regdeletekey')
              ,OBJECT_ID('xp_regdeletevalue')
              ,OBJECT_ID('xp_regenumvalues')
              ,OBJECT_ID('xp_regenumkeys')
              ,OBJECT_ID('xp_regremovemultistring')
              ,OBJECT_ID('xp_regwrite')
              ,OBJECT_ID('xp_instance_regaddmultistring')
              ,OBJECT_ID('xp_instance_regdeletekey')
              ,OBJECT_ID('xp_instance_regdeletevalue')
              ,OBJECT_ID('xp_instance_regenumkeys')
              ,OBJECT_ID('xp_instance_regenumvalues')
              ,OBJECT_ID('xp_instance_regremovemultistring')
              ,OBJECT_ID('xp_instance_regwrite')
            )
            AND dp.[type] = 'EX'
          )
          SELECT
          count(*) as results
          FROM cte_temp;
          "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.results){
              {$_ -gt 0} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 14
Function Run-Finding214032{
      param(
          $enclave
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214032'
      $remediate_file_name       = 'Remediate-SQL_Server_Service_Broker_Endpoint.md'
      $check_description         = 'SQL Server Service Broker endpoint must utilize AES encryption.'
      $cat_level                 = '2'
      #----------------#
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = ([string](Get-SqlInstances).Keys)
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -ErrorAction stop
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
 
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_using_tls'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'using_tls'
          }
      }
 
      if($CheckResultsTable.status -eq 'using_tls'){
          $CheckResultsTable.check_results = 'using_tls'
      }else{
       $CheckResultsTable.check_results = 'not_using_tls'
      }
          switch($CheckResultsTable.check_results){
              'not_using_tls' {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $check_description. Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              'using_tls' {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $check_description. Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
     
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 15
Function Run-Finding214031{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214031'
      $remediate_file_name       = 'Remediate-Server_Mirroring_Endpoint.md'
      $check_description         = 'SQL Server Mirroring endpoint must utilize AES encryption.'
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      SELECT
          count(is_encryption_enabled) as [Results]
      FROM sys.database_mirroring_endpoints;"
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.Results){
              {$_ -gt 0} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 16
Function Run-Finding214030{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214030'
      $remediate_file_name       = 'Remediate-Startup_Stored_Procedurest.md'
      $check_description         = 'Execution of startup stored procedures must be restricted to necessary cases only.'
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      Select count([name]) as Results
      From sys.procedures
      Where OBJECTPROPERTY(OBJECT_ID, 'ExecIsStartup') = 1"
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.Results){
              {$_ -gt 0} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 17
Function Run-Finding214029{
      param(
           [string[]]$InstanceName,
              $enclave,
              $ProcessName = "Invoke-UDFSQLCommand"
      )
      #----------------# server_level
      $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
      $finding_id                = 'V-214029'
      $remediate_file_name       = 'Remediate-SQL_Server_Default_Account.md'
      $check_description         = 'SQL Server default account [sa] must have its name changed.'
      $cat_level                 = '2'
      #----------------#
 
      $databaseName = 'master'
      $TsqlCommand = "
      SELECT count(*) as Results
      FROM sys.sql_logins
      WHERE [name] = 'sa' OR [principal_id] = 1; "
 
      # sql connection to instance
      foreach($instance in $instancename){
          $sqlconnectionstring = "
              server                          = $instance;
              database                        = $databasename;
              trusted_connection              = true;
              application name                = $processname;"
          # sql connection, setup call
          $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
          $sqlconnection.connectionstring = $sqlconnectionstring
          $sqlconnection.open()
          $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
          $sqlcommand.connection          = $sqlconnection
          $sqlcommand.commandtext         = $tsqlcommand
          # sql connection, handle returned results
          $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
          $sqladapter.selectcommand       = $sqlcommand
          $dataset                        = new-object system.data.dataset
          $sqladapter.fill($dataset) | out-null
          $resultsreturned               += $dataset.tables
          $sqlconnection.close() # the session opens, but it will not close as expected
          $sqlconnection.dispose() # TO-DO: make sure the connection does close
      }
 
      $CheckResultsTable = @{
          finding_id           = $finding_id
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $InstanceName[0]
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          check_completed      = [bool]
          comments             = [string]
          check_results        = [psobject]
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
      try{
          $CheckResultsTable.check_completed  = $true
          $CheckResultsTable.check_results    = $resultsreturned
     
      }catch{
          $CheckResultsTable.check_completed  = $false
          $CheckResultsTable.check_results    = $Error[0]
      }
 
      $CheckResultsTable.add('status', [bool])
      # if the check results dont complete, status is set to not_reviewed
      switch($CheckResultsTable.check_completed){
          $false {
              $CheckResultsTable.status = 'not_reviewed'
          }
          $true{
              # if the check did complete, what do we do?
              $CheckResultsTable.status = 'evaluate'
          }
      }
 
      if($CheckResultsTable.status -eq 'evaluate'){
          switch($CheckResultsTable.check_results.Results){
              {$_ -gt 0} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 18
Function Run-Finding214028{
    param([string]$InstanceName,[string]$enclave)

  $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
  $finding_id                = 'V-214028'
  $remediate_file_name       = 'Remediate-SQL-SA_Account_Disabled.md'
  $check_description         = 'The SQL Server default account [sa] must be disabled.'
  $cat_level                 = '1'

  # check to see uwhat if any script will be ran
  $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
  if($scripts_to_rn -eq 0){
      $no_checks_run_scripts = $true
  }else{
      $no_checks_run_scripts = $false
  }

  # only when there is scripts to run do we care to do this step
  $checks_list = @()
  $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
  $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script


  if($no_checks_run_scripts -eq $false){
    switch($check_type){
        'sql_instance_check'{
        $checks_list += 'sql_instance_check'
            $is_sql_instance_check = $true
            $Query_Params = @{
                instance_name   = $InstanceName
                database_name   = 'master'
                query           = $check_todo
            }
        }
    }
  }


  $check_results_table = @{}
  # here we do the checks that will query a database
  if($is_sql_instance_check){
      [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
      $check_results_table.Add('sql_instance_check',$sql_query_result)
  }


  # the results are evaluated by the type of check, the exections are evaluated
  $my_considerations = @{
      remarks = 'mixed mode is not used'
  }
  if($check_results_table[$checks_list[0]].check_result  -eq 1){
    $status = 1
  }else{
    $status = 0
  }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }


      switch($status){
            {$_ -eq 0} {
                $CheckResultsTable.check_results = 'Open'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
            {$_ -eq 1} {
                $CheckResultsTable.check_results = 'not_a_finding'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
        }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 19
Function Run-Finding214027{
      param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214027'
    $remediate_file_name       = 'Remediate-SQL_Server_Usage_And_Error_Reporting.md'
    $check_description         = 'SQL Server must configure SQL Server Usage and Error Reporting Auditing.'
    $cat_level                 = '2'

    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_run -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    if($no_checks_run_scripts -eq $false){
        foreach($check_todo in (Get-FindingChecks -finding_id $finding_id)){
            # asses what kind of check it is that we are doing

            $is_sql_instance_check = $false
            switch($check_todo.check_type){
                'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                    $is_sql_instance_check = $true
                    $Query_Params = @{
                        instance_name   = $InstanceName
                        database_name   = 'master'
                        query           = $check_todo.check_script
                    }
                }
            }

            $check_results_table = @{}
            # here we do the checks that will query a database
            if($is_sql_instance_check){
                [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
                $check_results_table.Add('sql_instance_check',$sql_query_result)
            }
        }
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = Get-FindingExceptions2 -finding_id $finding_id -CheckResults $check_results_table
    if($null -ne $my_considerations){
        foreach($check_done in $checks_list){
        $status = $my_considerations.$check_done.results.status
        }
    }

      # each instance will make a connection to the thing they need
      $CheckResultsTable = @{
          finding_id           = $finding_id
          considerations       = $my_considerations
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $instancename
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          comments             = [string]
          check_results        =  $status
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }

 
        switch($CheckResultsTable.check_results.status){
              {$_ -eq 'open'} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 'not_a_finding'} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 20
Function Run-Finding214026{
      param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214026'
    $remediate_file_name       = 'Remediate-SQL_Customer_Feedback_Error_Reporting.md'
    $check_description         = 'SQL Server must configure Customer Feedback and Error Reporting.'
    $cat_level                 = '2'

    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id  $finding_id)
    if($scripts_to_run -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    if($no_checks_run_scripts -eq $false){
        foreach($check_todo in (Get-FindingChecks -finding_id $finding_id)){
            # asses what kind of check it is that we are doing

            $is_sql_instance_check = $false
            $is_ps_check = $false
            switch($check_todo.check_type){
                'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                    $is_sql_instance_check = $true
                    $Query_Params = @{
                        instance_name   = $InstanceName
                        database_name   = 'master'
                        query           = $check_todo.check_script
                    }
                }
                'ps_script'{
                    $checks_list += 'ps_script'
                    $is_ps_check = $true
   
                }
            }

            $check_results_table = @{}
            # here we do the checks that will query a database
            if($is_sql_instance_check){
                [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
                $check_results_table.Add('sql_instance_check',$sql_query_result)
            }

            if($is_ps_check){
                $reg_search_val = @()
                    $reg_search_val += 'MSSQL13.MSSQLSERVER'
                    $reg_search_val += "MSSQL13.$isntanceName"
                foreach($reachable in $reg_search_val){
                    try{
                        $reg_vals = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft SQL Server\$reachable\CPE\" -ErrorAction SilentlyContinue
   
                    }catch{

                    }
                    if($null -ne $reg_vals){
                        $the_results = $reg_vals.CustomerFeedback;break
                    }
                }
                $check_results = @{
                    check_result = $the_results
                    check_value =  $the_results
                    result_type = 'registry_check_forval_1'
                }
               $check_results_table =  $check_results
            }
        }
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = Get-FindingExceptions2 -finding_id $finding_id -CheckResults $check_results_table
    $status = $my_considerations.check_result

      # each instance will make a connection to the thing they need
      $CheckResultsTable = @{
          finding_id           = $finding_id
          considerations       = $my_considerations
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $instancename
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          comments             = [string]
          check_results        =  $status
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }

 
        switch($CheckResultsTable.check_results){
              {$_ -eq 1} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 21
Function Run-Finding214025{
      param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214025'
    $remediate_file_name       = 'Remediate-Off-load_audit_data_to_a_separate_log.md'
    $check_description         = 'SQL Server must off-load audit data to a separate log management facility.'
    $cat_level                 = '2'

    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_run -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    if($no_checks_run_scripts -eq $false){
        foreach($check_todo in (Get-FindingChecks -finding_id $finding_id)){
            # asses what kind of check it is that we are doing

            $is_sql_instance_check = $false
            switch($check_todo.check_type){
                'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                    $is_sql_instance_check = $true
                    $Query_Params = @{
                        instance_name   = $InstanceName
                        database_name   = 'master'
                        query           = $check_todo.check_script
                    }
                }
            }

            $check_results_table = @{}
            # here we do the checks that will query a database
            if($is_sql_instance_check){
                [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
                $check_results_table.Add('sql_instance_check',$sql_query_result)
            }
        }
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        remarks = 'unsure of logging is taking place in a any capacity to the degree the stig outlines.'
    }
    $status = 1

      # each instance will make a connection to the thing they need
      $CheckResultsTable = @{
          finding_id           = $finding_id
          considerations       = $my_considerations
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $instancename
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          comments             = [string]
          check_results        =  $status
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }

 
        switch($CheckResultsTable.check_results){
              {$_ -eq 1} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 22
Function Run-Finding214024{
      param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214024'
    $remediate_file_name       = 'Remediate-NIST-FIPS_140-2_or_140-3_cryptography.md'
    $check_description         = 'SQL Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules.'
    $cat_level                 = '2'

    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_run -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    if($no_checks_run_scripts -eq $false){
        foreach($check_todo in (Get-FindingChecks -finding_id $finding_id)){
            # asses what kind of check it is that we are doing

            $is_sql_instance_check = $false
            switch($check_todo.check_type){
                'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                    $is_sql_instance_check = $true
                    $Query_Params = @{
                        instance_name   = $InstanceName
                        database_name   = 'master'
                        query           = $check_todo.check_script
                    }
                }
            }

            $check_results_table = @{}
            # here we do the checks that will query a database
            if($is_sql_instance_check){
                [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
                $check_results_table.Add('sql_instance_check',$sql_query_result)
            }
        }
    }
    $reg_value_set = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
    $result = $reg_value_set.Enabled

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        remarks = 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
    }
    $status =   $result

      # each instance will make a connection to the thing they need
      $CheckResultsTable = @{
          finding_id           = $finding_id
          considerations       = $my_considerations
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $instancename
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          comments             = [string]
          check_results        =  $status
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }

 
        switch($CheckResultsTable.check_results){
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 1} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 23
Function Run-Finding214023{
      param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214023'
    $remediate_file_name       = 'Remediate-Validated_cryptographic_modules_to_generate_and_validate_cryptographic_hashes.md'
    $check_description         = 'SQL Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to generate and validate cryptographic hashes.'
    $cat_level                 = '1'

    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_run -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    if($no_checks_run_scripts -eq $false){
        foreach($check_todo in (Get-FindingChecks -finding_id $finding_id)){
            # asses what kind of check it is that we are doing

            $is_sql_instance_check = $false
            switch($check_todo.check_type){
                'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                    $is_sql_instance_check = $true
                    $Query_Params = @{
                        instance_name   = $InstanceName
                        database_name   = 'master'
                        query           = $check_todo.check_script
                    }
                }
            }

            $check_results_table = @{}
            # here we do the checks that will query a database
            if($is_sql_instance_check){
                [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
                $check_results_table.Add('sql_instance_check',$sql_query_result)
            }
        }
    }
    $reg_value_set = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
    $result = $reg_value_set.Enabled

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        remarks = 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
    }
    $status =   $result

      # each instance will make a connection to the thing they need
      $CheckResultsTable = @{
          finding_id           = $finding_id
          considerations       = $my_considerations
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $instancename
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          comments             = [string]
          check_results        =  $status
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }

 
        switch($CheckResultsTable.check_results){
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 1} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 24
Function Run-Finding214021{
      param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214021'
    $remediate_file_name       = 'Remediate-Generate_audit_records_for_all_direct_access.md'
    $check_description         = 'SQL Server must generate audit records for all direct access to the database(s).'
    $cat_level                 = '2'

    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_run -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    if($no_checks_run_scripts -eq $false){
        foreach($check_todo in (Get-FindingChecks -finding_id 'V-214021')){
            # asses what kind of check it is that we are doing

            $is_sql_instance_check = $false
            switch($check_todo.check_type){
                'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                    $is_sql_instance_check = $true
                    $Query_Params = @{
                        instance_name   = $InstanceName
                        database_name   = 'master'
                        query           = $check_todo.check_script
                    }
                }
            }

            $check_results_table = @{}
            # here we do the checks that will query a database
            if($is_sql_instance_check){
                [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
                $check_results_table.Add('sql_instance_check',$sql_query_result)
            }
        }
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = {remarks = 'the stig says the intent is to capture all activity from admin, and non standard source. jusdt because there isnt filters, doesnt mean its not a finding'}
    if( $null -ne $check_results_table){
        $status = 1
    }
    else{
    $status = 1}
      # each instance will make a connection to the thing they need
      $CheckResultsTable = @{
          finding_id           = $finding_id
          considerations       = $my_considerations
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $instancename
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          comments             = [string]
          check_results        =  $status
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }

 
        switch($CheckResultsTable.check_results){
              {$_ -eq 1} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 25
Function Run-Finding214020{
      param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214020'
    $remediate_file_name       = 'Remediate-Audit_successful-unsuccessful_access_to_objects.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful accesses to objects occur.'
    $cat_level                 = '2'

    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    if($no_checks_run_scripts -eq $false){
        foreach($check_todo in (Get-FindingChecks -finding_id  $finding_id)){
            # asses what kind of check it is that we are doing

            $is_sql_instance_check = $false
            switch($check_todo.check_type){
                'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                    $is_sql_instance_check = $true
                    $Query_Params = @{
                        instance_name   = $InstanceName
                        database_name   = 'master'
                        query           = $check_todo.check_script
                    }
                }
            }

            $check_results_table = @{}
            # here we do the checks that will query a database
            if($is_sql_instance_check){
                [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
                $check_results_table.Add('sql_instance_check',$sql_query_result)
            }
        }
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = {remarks = 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.'}
    $status = ($check_results_table.values.check_result)
   
      # each instance will make a connection to the thing they need
      $CheckResultsTable = @{
          finding_id           = $finding_id
          considerations       = $my_considerations
          ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
          host_name            = $instancename
          ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
          mac_address          = (Get-NetAdapter).macAddress
          cat                  = $cat_level
          check_description    = $check_description
          comments             = [string]
          check_results        =  $status
          enclave              = $enclave
          datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
          csv_formatted        = [string]
      }
     
 
 # this is a finding for sure
        switch(($status)){
              {$_ -eq 0} {
                  $CheckResultsTable.check_results = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 1} {
                  $CheckResultsTable.check_results = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
# funding 26
Function Run-Finding213934{
    param([string]$InstanceName,[string]$enclave)

  $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
  $finding_id                = 'V-213934'
  $remediate_file_name       = 'Remediate-SQL-Secure_NT_AUTHORITY_SYSTEM.md'
  $check_description         = 'SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration.'
  $cat_level                 = '1'

  # check to see uwhat if any script will be ran
  $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
  if($scripts_to_rn -eq 0){
      $no_checks_run_scripts = $true
  }else{
      $no_checks_run_scripts = $false
  }

  # only when there is scripts to run do we care to do this step
  $checks_list = @()
  $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
  $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script


  if($no_checks_run_scripts -eq $false){
    switch($check_type){
        'sql_instance_check'{
        $checks_list += 'sql_instance_check'
            $is_sql_instance_check = $true
            $Query_Params = @{
                instance_name   = $InstanceName
                database_name   = 'master'
                query           = $check_todo
            }
        }
    }
  }


  $check_results_table = @{}
  # here we do the checks that will query a database
  if($is_sql_instance_check){
      [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
      $check_results_table.Add('sql_instance_check',$sql_query_result)
  }


  # the results are evaluated by the type of check, the exections are evaluated
  $my_considerations = @{
      remarks = 'when checking to see the permission over allocation, the stig defines the finding as open or not given a set of conditions, those conditon where checked to asses finding'
  }
  if($check_results_table[$checks_list[0]].check_result  -eq 1){
    $status = 1
  }else{
    $status = 0
  }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }


      switch($status){
            {$_ -eq 1} {
                $CheckResultsTable.check_results = 'Open'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
            {$_ -eq 0} {
                $CheckResultsTable.check_results = 'not_a_finding'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
        }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 27
Function Run-Finding213932{
    param([string]$InstanceName,[string]$enclave)

  $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
  $finding_id                = 'V-213932'
  $remediate_file_name       = 'Remediate-Access_request_Form.md'
  $check_description         = 'SQL Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  $cat_level                 = '1'

  # check to see uwhat if any script will be ran
  $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
  if($scripts_to_rn -eq 0){
      $no_checks_run_scripts = $true
  }else{
      $no_checks_run_scripts = $false
  }

  # only when there is scripts to run do we care to do this step
  $checks_list = @()
  $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
  $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script


  if($no_checks_run_scripts -eq $false){
    switch($check_type){
        'sql_instance_check'{
        $checks_list += 'sql_instance_check'
            $is_sql_instance_check = $true
            $Query_Params = @{
                instance_name   = $InstanceName
                database_name   = 'master'
                query           = $check_todo
            }
        }
    }
  }


  $check_results_table = @{}
  # here we do the checks that will query a database
  if($is_sql_instance_check){
      [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
      $check_results_table.Add('sql_instance_check',$sql_query_result)
  }


  # the results are evaluated by the type of check, the exections are evaluated
  $my_considerations = @{
      remarks = 'there just needs to be a process in place that people can follow when it comes to requesting login/access to a database, till one is defined, this will be open'
  }
  $status = 1


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }


      switch($status){
            {$_ -eq 1} {
                $CheckResultsTable.check_results = 'Open'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
            {$_ -eq 0} {
                $CheckResultsTable.check_results = 'not_a_finding'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
        }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 28

Function Run-Finding214018{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214018'
    $remediate_file_name       = 'Remediate-Concurrent_Logons_Logs.md'
    $check_description         = 'SQL Server must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
    $cat_level                 = '2'
    # test
    # check to see uwhat if any script will be ran
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script
    $check_todo | clip.exe
    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
    remarks = 'you can also satify this finding by enabling of logging both successful and unsuccessful'
    }
    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }

    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }


      switch($status){
            {$_ -eq 1} {
                $CheckResultsTable.check_results = 'Open'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
            {$_ -eq 0} {
                $CheckResultsTable.check_results = 'not_a_finding'
                $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                $CheckResultsTable.comments = $comment_string
            }
        }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 29
Function Run-Finding214017{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214017'
    $remediate_file_name       = 'Remediate-Generate_Start_End_Logs.md'
    $check_description         = 'SQL Server must generate audit records showing starting and ending time for user access to the database(s).'
    $cat_level                 = '2'
   
    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        remarks = 'This is the same as the other findings that are about auditing for the most part.'
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }
    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 30
Function Run-Finding214016{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214016'
    $remediate_file_name       = 'Remediate-Generate_Start_End_Logs.md'
    $check_description         = 'SQL Server must generate audit records showing starting and ending time for user access to the database(s).'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        remarks = 'This is the same as the other findings that are about auditing for the most part.'
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }
    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 31
Function Run-Finding214015{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214015'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214015_Finding.md'
    $check_description         = 'SQL Server must generate audit records for all privileged activities or other system-level access.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'The specifications, this audit is in reference to, is already covered by a previous STIG.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }
    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = [string]
        check_results        =  $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 32
Function Run-Finding214014{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214014'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214014_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful logons or connection attempts occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the addition of 1 additional audit specifications that are not convered by the previous check of this kind SCHEMA_OBJECT_ACCESS_GROUP'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 33
Function Run-Finding214010{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214010'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214010_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful attempts to delete security objects occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind. Check to see if SCHEMA_OBJECT_CHANGE_GROUP is in the specifications for the STIG _Audit'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 34
Function Run-Finding214008{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214008'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214008_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful attempts to delete privileges/permissions occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 35
Function Run-Finding214006{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214006'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214006_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications SCHEMA_OBJECT_ACCESS_GROUP, that is already convered by the previous check of this kind.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 36
Function Run-Finding214004{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214004'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214004_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful attempts to modify security objects occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind. Check to see if SCHEMA_OBJECT_CHANGE_GROUP is in the specifications for the STIG _Audit'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 37
Function Run-Finding214002{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214002'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214002_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful attempts to modify privileges/permissions occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 38
Function Run-Finding214000{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214000'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-214000_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful attempts to add privileges/permissions occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 39
Function Run-Finding213998{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213998'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213998_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful and unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 40
Function Run-Finding213995{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213995'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213995_Finding.md'
    $check_description         = 'SQL Server must be able to generate audit records when successful and unsuccessful attempts to access security objects occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# funding 41
Function Run-Finding213939{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213939'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213939_Finding.md'
    $check_description         = 'SQL Server must generate audit records when successful/unsuccessful attempts to retrieve privileges/permissions occur.'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = 'This finding defines the an audit specifications that is already convered by the previous check of this kind.'
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    if($check_results_table[$checks_list[0]].check_result  -eq 1){
        $status = 1 # is a finding
    }else{
        $status = 0 # not a finding
    }


    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# finding 42
Function Run-Finding213994{
    param([string]$InstanceName,[string]$enclave,$this_kb)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213994'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213994_Finding.md'
    $check_description         = 'Security-relevant software updates to SQL Server must be installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
    $cat_level                 = '2'

    # check out the script to run for this finding, if any...
    $scripts_to_rn = (Get-FindingChecks -finding_id $finding_id)
    if($scripts_to_rn -eq 0){
        $no_checks_run_scripts = $true
    }else{
        $no_checks_run_scripts = $false
    }

    # only when there is scripts to run do we care to do this step
    $checks_list = @()
    $check_type = (Get-FindingChecks -finding_id $finding_id).check_type
    $check_todo = (Get-FindingChecks -finding_id $finding_id).check_script

    if($no_checks_run_scripts -eq $false){
        switch($check_type){
            'sql_instance_check'{
                $checks_list += 'sql_instance_check'
                $is_sql_instance_check = $true
                $Query_Params = @{
                    instance_name   = $InstanceName
                    database_name   = 'master'
                    query           = $check_todo
                }
            }
        }
    }

    $check_results_table = @{}
    # here we do the checks that will query a database
    if($is_sql_instance_check){
        [array]$sql_query_result = (Invoke-UDFSQLCommand -Query_Params $Query_Params)
        $check_results_table.Add('sql_instance_check',$sql_query_result)
    }
    # create a temp file in c:\temp
    $cache_dir = "C:\temp"
    $cache_file = '\last_time_check_for_sql_patches.log'

    $dir_exists = test-path $cache_dir
    if(-not($dir_exists)){
        New-Item -Path $cache_dir -ItemType 'Directory'
    }

    $cache_path = "$($cache_dir)$($cache_file)"
    $cache_file_created = [bool]
    if(-not(Test-Path $cache_path)){
        $cache_file_created = $true
        New-Item -Path  $cache_path -ItemType 'File' | Out-Null
    }else{
        $cache_file_created = $false
    }

    if($cache_file_created){
        $date_string = (get-date).ToString('yyyy-MM-dd HH:mm:ss')
        Set-Content -Value $date_string -path $cache_path
    }

    $datetimeString = Get-Content -Path $cache_path
    $format = "yyyy-MM-dd HH:mm:ss"
    $nullValue = $null
    $datetime = [DateTime]::ParseExact($datetimeString, $format, $nullValue)

    # check should be done every 3 weeks or 21 days
    $current_date_time = get-date
    $date_window = $current_date_time.AddDays(-21)

    # its a finding if not checked within the set 21 days
    if(-not($datetime -gt $date_window)){
        $check_patch_value = "the last time the patch was check was '$($datetime)', in compliance. {0}."
        $status = 0
    }else{
        $check_patch_value = "the last time the patch was check was '$($datetime)' out of compliance, check every '21' days. {0}"
        $status = 1
    }

    ($check_results_table[$checks_list[0]].check_result) -match '(.*) (\(KB.*\)) - (.*) \(.*\)'
    $product_version    = $matches[3]
    $KB                 = (($matches[2]).Replace('(','')).Replace(')','')

    $sql_version_stats = @{
        product_version = $product_version
        kb = $kb
    }
    if($sql_version_stats.kb -notmatch $this_kb){
        $check_kb_version_value =" You are running and older version then the one provided, remediate by patching."
        $status = 1
    }else{
       
        $status = 0
        $check_kb_version_value =" You are running the current version available of the SQL engine."
    }

    $Final_check_value = $check_patch_value -f $check_kb_version_value

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = $Final_check_value
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }



    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# finding 43
Function Run-Finding213993{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213993'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213993_Finding.md'
    $check_description         = 'When updates are applied to SQL Server software, any software components that have been replaced or made unnecessary must be removed.'
    $cat_level                 = '2'

    # create a temp file in c:\temp
    $software_dir = "C:\temp"
    $software_file = '\software_list.csv'

    $dir_exists = test-path $software_dir
    if(-not($dir_exists)){
        New-Item -Path $software_dir -ItemType 'Directory'
    }

    $software_path = "$($software_dir)$($software_file)"
    $software_file_created = [bool]
    if(-not(Test-Path $software_path)){
        $software_file_created = $true
        New-Item -Path  $software_path -ItemType 'File' | Out-Null
    }else{
        $software_file_created = $false
    }

    if($software_file_created){
        $installed_products = Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version
        $product_audit_table = @{}
        $product_audit_list = @()
        foreach($product_installed in $installed_products){
            $product_audit_table =  @{
                host_name =     $env:COMPUTERNAME
                software_name = $product_installed.name
                software_version = $product_installed.Version
            }
            $product_audit_list  += (ConvertFrom-Hashtable $product_audit_table)
        }
        $my_csv_data = ($product_audit_list | ConvertTo-Csv -NoTypeInformation)
        Set-Content -Value $my_csv_data -path $software_path
    }

    $software_list = (Get-Content -Path $software_path) | ConvertFrom-Csv

    $is_the_software_list_documented = [bool]
    if( $null -eq $software_list){
        $is_the_software_list_documented = $false
    }else{
        $is_the_software_list_documented = $true
    }

    if($is_the_software_list_documented){
        $check_value ="All software is documented. validate documentation exists in C:\temp on this host. Keep a copy of this documentation in a location appropriate for the content"
        $status = 0
    }else{
       
        $status = 1
        $check_value =" Software running on host is not documented."
    }

    $Final_check_value = $check_value

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = $Final_check_value
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }



    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}
# finding 44
Function Run-Finding213969{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213969'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213969_Finding.md'
    $check_description         = 'SQL Server must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.'
    $cat_level                 = '1'

   
    if ([System.Security.Cryptography.Cryptoconfig]::AllowOnlyFipsAlgorithms) {
        $Final_check_value = 'Fips Algorithms is enabled.'
        $status = 0
    } else {
        $Final_check_value = 'Fips Algorithms is not enabled.'
        $status = 1
    }

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = $Final_check_value
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }



    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}

# finding 44
Function Run-Finding213990{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213990'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213990_Finding.md'
    $check_description         = 'SQL Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.'
    $cat_level                 = '2'

    $processes_info  = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

    $sql_related_processes = (Get-Process -name "*SQL*")
    $process_collection = @()
    foreach($pi1d in $sql_related_processes){
     foreach($process_captured in $processes_info){
        $is_sql_proc = $process_captured | select * | where {$_.OwningProcess -eq $pi1d.id }
        if(-not($null -eq $is_sql_proc)){
        $by_hash = @{
            localport_used = $is_sql_proc.localport
            process_name = $pi1d.ProcessName
        }
            $process_collection += ConvertFrom-Hashtable $by_hash
           
        }
     }
    }
   
    $Final_check_value = 'Ports being used need to be documented.'
    $status = 1

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = $Final_check_value
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }



    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}

Function Run-Finding213988{
    param([string]$InstanceName,[string]$enclave)
    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-213989'
    $remediate_file_name       = 'Remediate-SQL_Instance_Lvl-213988_Finding.md'
    $check_description         = 'Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance.'
    $cat_level                 = '2'

    # get the administrator accounts on the host
    $groupResults   = Get-LocalGroupMember -Group "Administrators"
    $fromSender     = @{
        FolderPath      = '.\testoutput\'
        FileName        = 'Accounts.csv'
    }

    # define a path
    $accountFolderPath  = ($fromSender.FolderPath)
    $accountFileName    = ($fromSender.FileName)
    $accountFilePath    = "$($accountFolderPath)$($accountFileName)"

    # create the file is its not currently there
    if(-not(Test-Path -Path $accountFolderPath)){
        New-Item -ItemType Directory -Path $accountFolderPath | Out-Null
    }
    if(-not(Test-Path -Path $accountFilePath)){
        New-Item -ItemType File -Path $accountFilePath | Out-Null
    }
    
    # add info to the file
    $headingString  = [string]
    $myHostName     = HostName
    $headingsList   = @("RecordID","HostName","PrincipalSource","AccountName","Description")
    $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')
    $myContent = Get-Content -path $accountFilePath | ConvertFrom-Csv -Delimiter ","

    if(0 -eq [int]$myContent.count){
        Add-Content -Path $accountFilePath -Value $headingString 
    }

    if(0 -eq [int]$myContent.count){
        [int]$recordID = 1
    }else{
        [int]$recordID = [int]$myContent.RecordID[-1]+1
    }

    $myEntriesList  = @()
    foreach($accountName in $groupResults){
        $entryString    = [string]
        $myEntry        = @("$recordID","$myHostName","$accountName","NULL")
        $entryString    =  '"{0}"'-f ($entryString = $myEntry -join '","')
        $myEntriesList += $entryString
        $recordID       = ($recordID) + 1
    }

    Add-Content -Path $accountFilePath -Value $myEntriesList

    $status = 0

    # use considerations for a comment section
    # the results are evaluated by the type of check, the exections are evaluated
    $my_considerations = @{
        contanct_info    = "Check performed by : $env:USERNAME"
        date_check_done  = $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.000'))
        remarks          = $Final_check_value
        instructions     = "See '$($documentation_parent_path)$($remediate_file_name)' for additional documenatation on this finding and how to resolve it"
    }

    # each instance will make a connection to the thing they need
    $CheckResultsTable = @{
        finding_id           = $finding_id
        considerations       = $my_considerations
        ResolutionFile       = "$($documentation_parent_path)$($remediate_file_name)"
        host_name            = $instancename
        ipaddress            = ((Get-NetIPConfiguration).IPv4Address).IPAddress
        mac_address          = (Get-NetAdapter).macAddress
        cat                  = $cat_level
        check_description    = $check_description
        comments             = $my_considerations
        check_results        = $status
        enclave              = $enclave
        datetime_checked     = (get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        csv_formatted        = [string]
    }

    switch($status){
        {$_ -eq 1} {
            $CheckResultsTable.check_results = 'Open'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
        {$_ -eq 0} {
            $CheckResultsTable.check_results = 'not_a_finding'
            $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
            $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
            $CheckResultsTable.comments = $comment_string
        }
    }
    $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
    $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
    $CheckResultsTable
}


