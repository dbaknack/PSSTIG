$ErrorActionPreference = 'STOP'
cd ..
Import-Module .\PSUTILITIES
Import-Module .\PSCONNECT
Import-Module .\PSSTIG

<#
    Remove-Module PSSTIG
    Remove-Module PSUTILITIES
    Remove-Module PSCONNECT
#>


# runs the set up when first using tool
$PSSTIG = (PSSTIG)
$PSSTIG.Initalize(@{
    ParentFolderPath    = '.\PSSTIG\Data'
    DataSource          = 'SQLServerInstance'
})


# runs the set up when first using tool
$PSSTIGVIEWER = (PSSTIGVIEWER)
$PSSTIGVIEWER.Initalize(@{
    ExePath = "$STIGVIEWERPATH\STIG Viewer 3.exe"
})
$PSSTIGVIEWER.StartStigViewer()
$PSSTIGVIEWER.StopStigViewer()
$PSSTIGVIEWER.RestartStigViewer()

# 2.0 -   define credentials to be used
$PSCONNECT = (PSCONNECT)

$PSCONNECT.GetHostData(@{All = $true})
$PSCONNECT.GetHostData(@{All = $false})

$PSCONNECT.StashCredentials(@{
    CredentialAlias = "DEV-ADM"
    Credentials     = Get-Credential
})

ping VIPTO-POSH
$PSCONNECT | Get-Member
$PSCONNECT.GetStachedCredentials(@{
    CredentialAlias = "DEV-ADM"
})


# 3.0 -   create sessions to remote hosts
$PSCONNECT.CreateRemoteSession(@{
    Use = "Alias"
})

# 4.0 -   define levels
# how these are filtered needs to be reworked, but its ok for the moment...
$InstanceLevelParams = $PSSTIG.MyHostDataSet(@{
    DataSource  = "SQLServerInstance"
    Level       = "Instance"
})


# 5.0 -   perform checks
#----------------------------------------------------------------------------------------#1
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
#----------------------------------------------------------------------------------------#2
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
#----------------------------------------------------------------------------------------#3
$findingID = 'V-214045'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214045 @FunctionParams
}
#----------------------------------------------------------------------------------------#4
$findingID = 'V-214042'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        $HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        SourceDataFrom  = $PSSTIG.Configuration.Files.SQLRoleMembersList.Path
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214042 @FunctionParams
}
#----------------------------------------------------------------------------------------#5
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
#----------------------------------------------------------------------------------------#6
$findingID = 'V-214044'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214044 @FunctionParams
}
#----------------------------------------------------------------------------------------#7
$findingID = 'V-214041'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214041 @FunctionParams
}
# ----------------------------------------------------------------------------------------#8
$findingID = 'V-214040'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214040 @FunctionParams
}
# ----------------------------------------------------------------------------------------#9
$findingID = 'V-214039'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214039 @FunctionParams
}
# ----------------------------------------------------------------------------------------#10
$findingID = 'V-214038'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214038 @FunctionParams
}
# ----------------------------------------------------------------------------------------#11
$findingID = 'V-214037'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214037 @FunctionParams
}
# ----------------------------------------------------------------------------------------#12
$findingID = 'V-214036'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214036 @FunctionParams
}
# ----------------------------------------------------------------------------------------#13
$findingID = 'V-214035'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214035 @FunctionParams
}
# ----------------------------------------------------------------------------------------#14
$findingID = 'V-214034'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214034 @FunctionParams
}
# ----------------------------------------------------------------------------------------#15
$findingID = 'V-214033'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214033 @FunctionParams
}
# ----------------------------------------------------------------------------------------#16
$findingID = 'V-214032'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214032 @FunctionParams
}
# ----------------------------------------------------------------------------------------#17
$findingID = 'V-214031'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214031 @FunctionParams
}
# ----------------------------------------------------------------------------------------#18
$findingID = 'V-214030'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214030 @FunctionParams
}
# ----------------------------------------------------------------------------------------#19
$findingID = 'V-214029'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214029 @FunctionParams
}
# ----------------------------------------------------------------------------------------#20
$findingID = 'V-214028'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214028 @FunctionParams
}
# ----------------------------------------------------------------------------------------#20
$findingID = 'V-214027'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = $PSSTIG.GetSession(@{SessionName = $InstanceLevelParam.HostName})
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214027 @FunctionParams
}
# ----------------------------------------------------------------------------------------#21
$findingID = 'V-214026'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName        = $InstanceLevelParam.HostName
        FindingID       = $findingID
        Session         = (Get-PSSession -Name $HostName)
        CheckListName   = $InstanceLevelParam.CheckListName
        DisplayStatus   = $true
    }
    Invoke-Finding214026 @FunctionParams
}
# ----------------------------------------------------------------------------------------#21
$findingID = 'V-214025'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        CheckListName               = $InstanceLevelParam.CheckListName
        DocumentationFolderPath     = ".\PSSTIG\Documentation"
        DisplayStatus               = $true
    }
    Invoke-Finding214025 @FunctionParams
}
# ----------------------------------------------------------------------------------------#22
$findingID = 'V-214024'
foreach($InstanceLevelParam in $InstanceLevelParams){
    $FunctionParams = @{
        HostName                    = $InstanceLevelParam.HostName
        FindingID                   = $findingID
        Session                     = (Get-PSSession -Name $InstanceLevelParam.HostName)
        CheckListName               = $InstanceLevelParam.CheckListName
        DisplayStatus               = $true
    }
    Invoke-Finding214024 @FunctionParams
}
