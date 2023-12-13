$UDFunctions = [ordered]@{}
$UDFunctions.'Invoke-UDFSQLCommand' +=@{
    BlockName   = 'Invoke-UDFSQLCommand'
    Description = "Makes a connection to the sql instance running on the host"
    ExecCmd     = {&($UDFunctions.'Invoke-UDFSQLCommand').Scriptblock.command`
        -use_sql_login $use_sql_login`
        -sql_login_name $sql_login_name`
        -sql_login_password $sql_login_password`
        -instance_name $instance_name`
        -tsql_command $tsql_command`
        -process_name $process_name}
    ScriptBlock = @{
        Command = {
            param(
                [bool]$use_sql_login,
                [string]$sql_login_name,
                [securestring]$sql_login_password,
                [string]$instance_name,
                [string]$database_name,
                [string]$tsql_command,
                [string]$process_name
            )
        
        # depending if you're going to use sql login or not, the connection string will be built differently
        if($use_sql_login -eq $true){
            $connection_template 	= "
                server					= {0};
                database				= {1};
                trusted_connection		= {2};
                user id					= {3};
                integrated security		= {4};
                password				= {5};
                application name		= {6};"
            $connection_template = $connection_template -f
                $instance_name,
                $database_name,
                'false',
                $sql_login_name,
                'true',
                $sql_login_password,
                $process_name;
        }
        
        # this will run when using windows authentication
        if($use_sql_login -eq $false){
            $connection_template 	= "
                server				= {0};
                database			= {1};
                trusted_connection	= {2};
                application name	= {3};"
        
            $connection_template = $connection_template -f
                $instance_name,
                $database_name,
                'true',
                $process_name;
        }
        
        # here we use the connection string to open the sql connection
        $sqlconnection = new-object system.data.sqlclient.sqlconnection
        $sqlconnection.connectionstring = $connection_template
        $sqlconnection.open()
        
        $sqlcommand = new-object system.data.sqlclient.sqlcommand
        $sqlcommand.connection = $sqlconnection
        $sqlcommand.commandtext	= $tsql_command
        $sqladapter = new-object system.data.sqlclient.sqldataadapter
        $sqladapter.selectcommand = $sqlcommand
        
        $dataset = new-object system.data.dataset
        $sqladapter.fill($dataset) | out-null
        
        # close the connection when things are done
        $results_collection = @{[string]$($instance_name) = $dataset.tables}
        if($sqlconnection.state -match 'open'){
            $sqlconnection.close()
            $sqlconnection.dispose()
        }
        
        # this holds our results to return
        $results_collection
        }
    }
}

$InvokeUDFSQLCommand3Params = @{
    instance_name      = 'DEV-SQL01\SANDBOX01'
    database_name      = 'master'
    process_name       = 'test'
    use_sql_login      = $false
    tsql_command       = 'select * from sys.databases'
    sql_login_password = ConvertTo-SecureString -String 'na' -AsPlainText -Force
    sql_login_name     = 'na'
}


$issessions | ForEach-Object {
    Invoke-Command -Session $_ -ScriptBlock $UDFunctions.'Invoke-UDFSQLCommand'.ScriptBlock.Command -ArgumentList @InvokeUDFSQLCommand3Params -AsJob
}

$instance_name      = 'DEV-SQL01\SANDBOX01'
$database_name      = 'master'
$process_name       = 'test'
$use_sql_login      = $false
$tsql_command       = 'select * from sys.databases'
$sql_login_password = ConvertTo-SecureString -String 'na' -AsPlainText -Force
$sql_login_name     = 'na'



$host_name_list         =  @("")
$use_a_sql_connection   = $true
# here we open up all the session we need for all the host we are connecting to
foreach($host_name in $host_name_list){
    New-PSSession -ComputerName $host_name -name ("sessionfor_{0}" -f $host_name) -Credential $creds | Out-Null
}
$My_Sessions  = Get-PSSession -Name "sessionfor_*"
$My_Sessions  |ForEach-Object {
    Invoke-Command -ComputerName "" -Credential $creds -ScriptBlock $UDFunctions.'Invoke-UDFSQLCommand'.ScriptBlock.Command `
    -ArgumentList $use_sql_login,$sql_login_name,$sql_login_password,$instance_name,$database_name,$tsql_command,$process_name -AsJob
}


$test = Get-Job | Receive-Job