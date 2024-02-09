$ErrorActionPreference = 'STOP'
Import-Module C:\LocalRepo\PSUTILITIES\PSUTILITIES.psd1
Import-Module .\PSSTIG.psd1 -DisableNameChecking
Remove-Module PSSTIG
# 1.1 -   runs the set up when first using tool
$PSSTIG = PSSTIG
$PSSTIG.AddData(@{
    DataSource = ".\Private\HOSTDATA.csv"
})
$PSSTIG.HOSTDATA
get-content -Path ".\Private\HOSTDATA.csv"
$PSSTIG.Initalize(@{
    ParentFolderPath    = '.\Data'
    DataSource          = 'SQLServerInstance'
})

$PSSTIGVIEWER = PSSTIGVIEWER

$PSSTIGVIEWER.Initalize(@{ExePath = "C:\Users\abraham.hernandez\Documents\Software\STIGViewer_64_3-2-0\STIG Viewer 3.exe"})
$PSSTIGVIEWER.StartStigViewer()
$PSSTIGVIEWER.StopStigViewer()
$PSSTIGVIEWER.RestartStigViewer()
# 2.0 -   define credentials to be used
$myCreds = Get-Credential

# 3.0 -   create sessions to remote hosts
$PSSTIG.CreateSessions(@{
    All         = $true
    HostList    = @()
    Creds       = $myCreds
})

# 4.0 -   define levels
# how these are filtered needs to be reworked...
$InstanceLevelParams = $PSSTIG.MyHostDataSet(@{
    DataSource  = "SQLServerInstance"
    Level       = "Instance"
})


# 5.0 -   perform checks
#----------------------------------------------------------------------------------------#
# Finding:V-213988
$findingID = 'V-213988'
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
Get-PSSession
#----------------------------------------------------------------------------------------#
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
    Invoke-Finding213987 @FunctionParams
}
#----------------------------------------------------------------------------------------#
$findingID = 'V-214045'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-FindingV214045 @FunctionParams
}
#----------------------------------------------------------------------------------------#
$findingID = 'V-214042'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214042 @FunctionParams
}
#----------------------------------------------------------------------------------------#
$findingID = 'V-214043'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214043 @FunctionParams
}
#----------------------------------------------------------------------------------------#
$findingID = 'V-214044'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214044 @FunctionParams
}



$PSCONNECT = [PSCONNECT]::new(@{
    FilePath = ".\Private\HOSTDATA.csv"
})

$myHostData = Get-Content -path ".\Private\HOSTDATA.csv" | ConvertFrom-Csv

$useAlias = $true
if($useAlias){
    $sessionParams = @{
        Name            = $myHostData.Alias
        ComputerName    = $myHostData.FQDN
        Port            = $myHostData.Port
        Credential      = $myCreds
        ErrorAction     = "Stop"
    }
}

New-PSSession @sessionParams

$SQLInstances = 
'sql2','sql4' | Get-DbaInstanceProperty
$results = Invoke-Command -Session (Get-PSSession -Name "DEV-SQL01") -ScriptBlock ${Function:Get-DbaInstanceProperty}
$results['DEV-SQL01']