#-------------------------------------------------> [ module utilities ]
Function Get-MyModulePath {
    $PSScriptRoot_String = $PSScriptRoot
    $PathStringLength = ($PSScriptRoot_String).Length
    # this removed the reference to the private folder
    $ModulePath  = $PSScriptRoot_String.Substring(0,($PathStringLength -7))
    $ModulePath
}
#-------------------------------------------------> [ module utilities ]
Function PSSTIG {
    $PSSTIG =  [PSSTIG]::new()
    $PSSTIG
}
Function Get-SqlInstances{

    Param($ServerName = [System.Net.Dns]::GetHostName())
   
 
    $LocalInstances = @()
 
    [array]$Captions = Get-WmiObject win32_service -ComputerName $ServerName |
      Where-Object {
        $_.Name -match "mssql*" -and
        $_.PathName -match "sqlservr.exe"
      } |
        ForEach-Object {$_.Caption}
 
    foreach ($Caption in $Captions) {
      if ($Caption -eq "MSSQLSERVER") {
        $LocalInstances += "MSSQLSERVER"
      } else {
        $Temp = $Caption |
          ForEach-Object {$_.split(" ")[-1]} |
          ForEach-Object {$_.trimStart("(")} |
            ForEach-Object {$_.trimEnd(")")}
 
        $LocalInstances += "$ServerName\$Temp"
      }
 
    }
 
     $instance_names_list = @()
     $instance_ruid = 1
    foreach($localinstance_name in $LocalInstances){
      # if the instance name is not a named instance, this condition will be true
      if($localinstance_name -match '(.*)\\(MSSQLSERVER)'){
         $instance_names_list += [pscustomobject]@{
          id = $instance_ruid
          host_name = $ServerName
          instance_type = 'unnamed'
          instance_name = $matches[1]
          }
      }else{
          $instance_names_list += [pscustomobject]@{
              id = $instance_ruid
              host_name = $ServerName
              instance_type = 'named'
              instance_name =  $localinstance_name
          }
      }
      $instance_ruid = $instance_ruid + 1
    }
    $instance_names_list | Group-Object -Property host_name -AsHashTable
}
Function PSSTIGVIEWER{
    $PSSTIGVIEWER = [PSSTIGVIEWER]::new()
    $PSSTIGVIEWER
}
Function PSSTIGMANUAL{
    $PSSTIGMANUAL = [PSSTIGMANUAL]::new()
    $PSSTIGMANUAL
}
Function Invoke-UDFSQLCommand{
    param(
        [hashtable]$Query_Params
    )

    $processname = 'Invoke-UDFSQLCommand'
    $myQuery = "{0}" -f $Query_Params.Query
    $sqlconnectionstring = "
        server                          = $($Query_Params.InstanceName);
        database                        = $($Query_Params.DatabaseName);
        trusted_connection              = true;
        application name                = $processname;"
    # sql connection, setup call
    $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
    $sqlconnection.connectionstring = $sqlconnectionstring
    $sqlconnection.open()
    $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
    $sqlcommand.connection          = $sqlconnection
    $sqlcommand.commandtext         = $myQuery
    # sql connection, handle returned results
    $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
    $sqladapter.selectcommand       = $sqlcommand
    $dataset                        = new-object system.data.dataset
    $sqladapter.fill($dataset) | out-null
    $resultsreturned                = $null
    $resultsreturned               += $dataset.tables
    $sqlconnection.close()      # the session opens, but it will not close as expected
    $sqlconnection.dispose()    # TO-DO: make sure the connection does close
    $resultsreturned
}
Function Invoke-PSSQL{
    param([hashtable]$Params)

    try{
        $SQLScript  = (Get-Content -Path (Get-ChildItem -path $Params.SQLScriptFolder -Filter "$($Params.SQLScriptFile).sql").FullName) -join "`n"
        $Params.ConnectionParams.Add("Query",$SQLScript)
    }catch{
        $Error[0] ; break
    }
    
    
    $InvokeParams = @{
        Session         = $Params.Session
        ArgumentList    = @{
            Func        = ${Function:Invoke-UDFSQLCommand}
            FuncParams  = $Params.ConnectionParams
        }
        ScriptBlock     = {
            param($ArgumentList)
            $ScriptBlock    = [scriptblock]::Create($ArgumentList.Func)
            $ArgumentList   = $ArgumentList.FuncParams
            Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        }
    }
    Invoke-Command @InvokeParams | select-object -Property * -ExcludeProperty "RunSpaceID"
}
Function Invoke-PSCMD{
    param([hashtable]$Params)
    begin{
        try{
            $PwshScript = (Get-Content -path (Get-ChildItem -path $Params.PowerShellScriptFolder -Filter "$($Params.PowerShellScriptFile).ps1").FullName) -join "`n"
        }catch{
            $Error[0]
        }
    }
    process{
        $results = $null
        foreach($Session in $Params.Session){
            $InvokeParams   = @{
                Session         = $Session
                ArgumentList    = @{
                    Func        = $PwshScript
                    FuncParams  = $Params.ArgumentList
                }
                ScriptBlock     = {
                    param($ArgumentList)
                    $ScriptBlock    = [scriptblock]::Create($ArgumentList.Func)
                    $ArgumentList   = $ArgumentList.FuncParams
                    Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
                }
            }

            $results = switch($Params.AsJob){
                $true   {
                    (Invoke-Command @InvokeParams -AsJob | Out-Null)
                }
                $false  {
                    (Invoke-Command @InvokeParams)
                    }
            }
        }
    }
    end{
        return $results
    }
}
Function Get-TargetData{
    param(
        [string]$CheckListName,
        [psobject]$Session
    )
    $myCheckListFolderPath  = $PSSTIG.Configuration.Folders.CheckLists.Path
    $myCheckListFile        = Get-ChildItem -Path $myCheckListFolderPath -Filter "$CheckListName.cklb"

    $myCheckListData = $PSSTIG.GetCheckListData(@{
        CheckListName = $CheckListName
    })

    $technologyArea = switch(($PSSTIG.PlatformParameters.OS)){
        "onWindows" {"Windows OS"}
    }

    $myResults = Invoke-Command -Session $Session -ScriptBlock {
        $MACAddress     = (Get-NetAdapter)[0] | Select-Object MacAddress
        $IPv4           = (Get-NetIPConfiguration)[0] | Select-Object IPv4Address
        $FQDN           = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
        $HostName       = HostName
        $myResults = @{
            MACAddress = $MACAddress
            IPV4        = $IPv4
            FQDN        = $FQDN
            HostName    = $HostName
        }
        $myResults
    }
    $myResults.Add("TechnologyArea",$technologyArea)

    $myTargetData                   = $myCheckListData.target_data
    $myTargetData.host_name         = $myResults.HostName
    $myTargetData.ip_address          = $myResults.IPV4.IPv4Address.IPAddress
    $myTargetData.mac_address       = $myResults.MACAddress.MacAddress
    $myTargetData.technology_area   = $technologyArea
    $myTargetData.fqdn              = $myResults.FQDN
    $myCheckListData.target_data    = $myTargetData

    $myCheckListDataConverted = $myCheckListData | ConvertTo-Json -Depth 5
    Set-Content -path  $myCheckListFile.FullName -Value $myCheckListDataConverted
}
Function Get-PSTIGModuleLocation{
    $myFunctionsPath = $PSCommandPath
    #TODO: on mac you wont be able to split on that separator
    $mySeparator = '\'
    $pathList = $myFunctionsPath.Split($mySeparator)
    $pathListCount = ($PathList.count -3)

    $modulePathList = @()
    foreach($pathItem in 0..$pathListCount){
        $modulePathList += $pathList[$pathItem]
    }
    $modulePathList -join $mySeparator
}
Function Get-DocumentSource{
    param(
        [string]$FolderPath,
        [string]$FileName
    )
    # check folder exists
    if(-not(test-path -path $FolderPath)){
        try{
            new-item -itemtype Directory -path $FolderPath | out-null
        }catch{
            write-Error -message $error[0]
        }
    }

    $filepath = ("{0}{1}" -f $FolderPath,$FileName)
    if(-not(Test-Path -path $filepath)){
        try{
            new-item -itemtype File -path $filepath | out-null
        }catch{
            write-Error -message $error[0]
        }
    }
    $filepath
}
Function Get-DocumentSourceSchema{
    param(
        [string]$SourceName
    )

    switch($SourceName){
        "Niper - Concurrent Sessions Per User"{
            $Schema = @{}
            $Schema.Add("PropertyList",@("RecID","HostName","InstanceName","MaxConcurrentSessionByAccountType","Set","DateSet","SetBy","LastChecked"))
            $Schema.Add("AsString",('"{0}"' -f ($Schema.PropertyList  -join '","')))

            $Schema.Add("DefaultValues",[pscustomObject]@{
                RecID                               = 0
                HostName                            = [string]
                InstanceName                        = [string]
                MaxConcurrentSessionByAccountType   = 0
                Set                                 = "notSet"
                DateSet                             = "notSet"
                SetBy                               = "notSet"
                LastChecked                         = (Get-Date).ToString("yyyy-MMd-dd HH:mm:ss")
            })
            $Schema
        }
        "Niper - SQLServer Installed Features"{
            $Schema = @{}
            $Schema.Add("PropertyList",@("RecID",
            "HostName",
            "InstanceName",
            "SQL Server Version",
            "Service Pack Level",
            "Edition",
            "Engine Edition",
            "Is Clustered",
            "Full-Text Installed",
            "Integrated Security Only",
            "Always On Availability Groups Enabled",
            "PolyBase Installed",
            "Replication Installed"))
            $Schema.Add("AsString",('"{0}"' -f ($Schema.PropertyList  -join '","')))

            $Schema.Add("DefaultValues",[pscustomObject]@{
                RecID                               = 0
                HostName                            = [string]
                InstanceName                        = [string]
                "SQL Server Version"                = "null"
                "Service Pack Level"                = "null"
                "Edition"= "null"
                "Engine Edition"= "null"
                "Is Clustered"= "null"
                "Full-Text Installed"= "null"
                "Integrated Security Only"= "null"
                "Always On Availability Groups Enabled"= "null"
                "PolyBase Installed"= "null"
                "Replication Installed"= "null"
            })
            $Schema
        }
        "Niper - Approved SQLLogins List"{
            $Schema = @{}
            $Schema.Add("PropertyList",@("RecID",
            "HostName",
            "InstanceName",
            "Account",
            "isApproved",
            "isDisabled",
            "Description"))
            $Schema.Add("AsString",('"{0}"' -f ($Schema.PropertyList  -join '","')))

            $Schema.Add("DefaultValues",[pscustomObject]@{
                RecID                               = 0
                HostName                            = [string]
                InstanceName                        = [string]
                "Account" = "NULL"
                "isApproved"= "NULL"
                "isDisabled"= "NULL"
                "Description"= "NULL"
            })
            $Schema
        }
        "Niper - Intances with CLR Configured"{
            $Schema = @{}
            $Schema.Add("PropertyList",@("RecID",
            "HostName",
            "InstanceName",
            "isApproved",
            "Description"))
            $Schema.Add("AsString",('"{0}"' -f ($Schema.PropertyList  -join '","')))

            $Schema.Add("DefaultValues",[pscustomObject]@{
                RecID           = 0
                HostName        = [string]
                InstanceName    = [string]
                isApproved      = $false
                Description     = "NULL"
            })
            $Schema
        }
        "Niper - SQL Services and Service Accounts"{
            $Schema = @{}
            $Schema.Add("PropertyList",@("RecID",
            "DomainName"
            "HostName",
            "name",
            "Account"))
            $Schema.Add("AsString",('"{0}"' -f ($Schema.PropertyList  -join '","')))

            $Schema.Add("DefaultValues",[pscustomObject]@{
                RecID       = 0
                DomainName  = [string]
                HostName    = [string]
                Name        = [string]
                Account     = [string]
            })
            $Schema
        }
        "Niper - SQL Server NetInfo"{
            $Schema = @{}
            $Schema.Add("PropertyList",@("RecID",
            "HostName",
            "InstanceName",
            "Interface",
            "UseDynamicPort",
            "UseStatic"
            "DynamicPort",
            "StaticPort",
            "isApproved",
            "ApprovedPort"))
            $Schema.Add("AsString",('"{0}"' -f ($Schema.PropertyList  -join '","')))

            $Schema.Add("DefaultValues",[pscustomObject]@{
                RecID           = 0
                HostName        = [string]
                InstanceName    = [string]
                UseDynamicPort  = $false
                UseStatic       = $false
                DynamicPort     = [string]
                StaticPort      = [string]
                isApproved      = "Static"
                ApprovedPort    = "1433"
            })
            $Schema
        }
        "Niper - Server Installed Software"{
            $Schema = @{}
            $Schema.Add("PropertyList",@("RecID",
            "HostName",
            "InstanceName",
            "DisplayName",
            "DisplayVersion",
            "iSApproved"))
            $Schema.Add("AsString",('"{0}"' -f ($Schema.PropertyList  -join '","')))

            $Schema.Add("DefaultValues",[pscustomObject]@{
                RecID           = 0
                HostName        = [string]
                InstanceName    = [string]
                DisplayName     = [string]
                DisplayVersion  = [string]
                iSApproved      = $false
            })
            $Schema
        }
        default {
            Write-Error -Message "$SourceName - does not have any defined schema or default values."
            #Approved SQLLogins List
        }
    }
}
Function Read-DocumentSource{
    param(
        [string]$DocumentSourcePath
    )

    $myContent = Get-Content -path $DocumentSourcePath
    $converted = $myContent | ConvertFrom-Csv

    $myData = @{
        TotalEntries = (($converted) | Measure-Object).COUNT
        Data        = $converted
    }

    $Separator = $PSSTIG.Separator
    $DocumentSourceName = ($DocumentSourcePath.Split($Separator)[-1]).Split('.')[0]
    if($myData.TotalEntries -eq 0){
        if($null -eq $myData.Data){
            $SourceProperties  = Get-DocumentSourceSchema -SourceName $DocumentSourceName
            Add-Content -Path $DocumentSourcePath -Value $SourceProperties.AsString
        }
    }

    $myContent = Get-Content -path $DocumentSourcePath
    $converted = $myContent | ConvertFrom-Csv
    $myData = @{
        TotalEntries = (($converted) | Measure-Object).COUNT
        Data        = $converted
        Schema      = Get-DocumentSourceSchema -SourceName $DocumentSourceName
    }
    return $myData
}

#-------------------------------------------------> [ audit functions ]
Function Invoke-Finding213988{
    param(
        [string]$Hostname,
        [string]$FindingID,
        [psobject]$Session,
        [string]$SourceDataFrom,
        [string]$CheckListName,
        [string]$CheckListType,
        [switch]$DisplayStatus
    )
   
    $FUNCTION_NAME  = "Invoke-Finding213988"
    # this host has issues with the cmdlet, not sure why
    if($Hostname -eq "PETERESNSWSQL01"){
        $results = net localgroup administrators
        $results = $results -split "`n" | Select-Object -Skip 6
        $newResults = @()
        foreach($result in $results){
            if(($result -ne 'The command completed successfully.')){
               $newResults += $result
            }
        }
        $finalResults = @()
        foreach($result in $newResults){
            if(($result -ne '')){
               $finalResults += $result
            }
        }
        $groupResults = @()
        foreach($finalResult in $finalResults){
            $groupResults += [pscustomobject]@{Name = $finalResult ; PrincipalSource = 'ActiveDirectory'}
        }
    }else{
        $groupResults  = Invoke-Command -Session $Session -ScriptBlock {Get-LocalGroupMember -Group "Administrators"}
    }
    if(-not(Test-Path -Path $SourceDataFrom)){
        New-Item -ItemType File -Path $SourceDataFrom | Out-Null
    }
    $myContent      = Get-Content -path $SourceDataFrom | ConvertFrom-Csv -Delimiter ","
    $headingString  = [string]
    $myHostName     = Invoke-Command -Session $Session -ScriptBlock {hostname}
    $headingsList   = @("RecordID","HostName","Name","PrincipalSource","Description")
    $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')


    if(0 -eq [int]$myContent.count){
        Add-Content -Path $SourceDataFrom -Value $headingString
    }

    if(0 -eq [int]$myContent.count){
        [int]$recordID = 1
    }else{
        [int]$recordID = [int]$myContent.RecordID[-1]+1
    }
   
    $myEntriesList  = @()
    foreach($accountName in $groupResults){
        $entryString    = [string]
        $myEntry        = @("$recordID","$myHostName","$($accountName.Name)","$($accountName.PrincipalSource)","NULL")
        $entryString    =  '"{0}"'-f ($entryString = $myEntry -join '","')
        $myEntriesList += $entryString
        $recordID       = ($recordID) + 1
    }
   
    $newEntriesList         = $myEntriesList | ConvertFrom-Csv -Header $headingsList
    $myCurrenEntriesTable   = $myContent | Group-Object -Property 'HostName' -AsHashTable

    $findingStatus          = "not_a_finding"
    $nullDescriptionList    = @()
    $noEntryExistsList      = @()
    $noAccountNameExistList = @()
    foreach($newEntry in $newEntriesList){
        $newEntryHostName = $newEntry.HostName
        $currentEntriesObject = $myCurrenEntriesTable.$newEntryHostName
       
       
        # are there entries for this hostname?
        $HostNameEntryExists = [bool]
        if($currentEntriesObject.HostName.count -eq 0){
            $HostNameEntryExists = $false
        }else{
            $HostNameEntryExists = $true
        }

        # if the entry doesnt already exist, then it gets added
        if(-not($HostNameEntryExists)){
            $myEntry = ('"{0}","{1}","{2}","{3}","{4}"' -f
                $newEntry.RecordID,
                $newEntry.HostName,
                $newEntry.Name,
                $newEntry.PrincipalSource,
                $newEntry.Description)
            Add-Content -Path $SourceDataFrom -Value $myEntry
            $findingStatus      = "open"
            $noEntryExistsList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }
        # is the name of the account in the list?
        $accountNameExists = [bool]
        if(-not($currentEntriesObject.Name -contains $newEntry.Name)){
            $accountNameExists = $false
        }else{
            $accountNameExists = $true
        }

        if( $accountNameExists -eq $false){
            $findingStatus          = "open"
            $noAccountNameExistList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }

        $currentEntryCheck = $currentEntriesObject |
            Select-Object -Property @('Name','Description') |
            Where-Object {$_.Name -eq ($newEntry.name)}

        $entryDescriptionIsNUll = $currentEntryCheck.Description -match 'NULL'
       
        if($entryDescriptionIsNUll){
            $findingStatus          = "open"
            $nullDescriptionList += [pscustomobject]@{HostName = $newEntry.HostName ; Name = $newEntry.Name}
        }
    }

    $checkedBy      = "{0} {1}" -f "Check performed by:",$env:USERNAME
    $dateChecked    = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    $myCommentList = @()
    if($findingStatus -eq "open"){
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += "'$SourceDataFrom' is used to document all admin account for '$($myHostName)'."
        $myCommentList += "All account need to be documented with a description, the following account are missing a description:"
        $myCommentList += ' '
        foreach($nullValue in $nullDescriptionList){
            $myCommentList +=  "   Host - '$($nullValue.HostName)', admin account '$($nullValue.Name)' is not documentend."
        }
    }else{
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += "'$SourceDataFrom' is used to document all admin account for '$($myHostName)'."
        $myCommentList += "All account need to be documented with a description, the following account are missing a description:"
    }
   
   
    $PSSTIG.UpdateComment(@{
        CheckListName   = $CheckListName
        FindingID       = $FindingID
        Comment         = ($myCommentList -join "`n")
    })
   
    $PSSTIG.UpdateStatus(@{
        CheckListName   = $CheckListName
        FindingID       = $FindingID
        Status          = $findingStatus
    })

    $updatedTargetData = [bool]
    try{
        $updatedTargetData = $true
        Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
    }catch{
        $updatedTargetData = $false
    }

    if($updatedTargetData -eq $false){
        $PSSTIG.PSUTILITIES.DisplayMessage(@{
            Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
            Category = "feedback"
            Type = "warning"
        })
    }

    if($DisplayStatus){
        $PSSTIG.GetFindingInfo(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
    }
}
Function Invoke-Finding213987{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$SourceDataFrom,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )

    $FUNCTION_NAME = "Invoke-Finding213987"
    $myScripts = $PSSTIG.GetSQLQuery(@{
        FindingID = $FindingID
    })
    # this script is not working in terms of its definiton as a query param, string is used instead for now
    #$principalsScript   = $myScripts['script_01']
   


    $instanceNameList   = $CheckListName -split '_'
    $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

    # run first check
    $SQLCommandParams = @{
        DatabaseName    = "master"
        InstanceName    = $instanceName
        Query           = @'

        -- table for final results
        declare @finalAssesment table (
            CheckResult         int,            -- either 1 for a finding 0 for not a finding
            ResultValue         nvarchar(100),  -- what value was evaluated
            ResultDescripton    nvarchar(100)   -- check description
        )
                       
        declare
            @finding_condition_met  int
            ,@CheckResult           int
            ,@ResultValue           varchar(100)
            ,@ResultDescripton      varchar(100)
       
        -- finding condition is initalized to 0
        set @finding_condition_met = 0
       
        -- filter out internal system only principals
        ;with cte_Principals as
        (
            select *
            from (
                select *
                from (
                    SELECT p.name AS Principal,
                    p.type_desc AS Type,
                    sp.permission_name AS Permission,  
                    sp.state_desc AS State
                    FROM sys.server_principals p
                    INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id
                    WHERE sp.permission_name = 'CONTROL SERVER'
                    OR sp.state = 'W'
                ) MyPrincipals
                where Principal not like ('##MS_SchemaSigningCertificate%')
            ) FilteredLikePrincipal
            where Principal not in (
                '##MS_AgentSigningCertificate##'
               ,'##MS_PolicySigningCertificate##'
               ,'##MS_SmoExtendedSigningCertificate##'
               ,'##MS_SQLAuthenticatorCertificate##'
               ,'##MS_SQLReplicationSigningCertificate##'
               ,'##MS_SQLResourceSigningCertificate##'
            )
        )
        select @ResultValue = (count(*))
        from cte_Principals
       
        if(@ResultValue) != '0'
        begin
            set @finding_condition_met  = 1
            set @ResultDescripton       = 'Principal other than internal ones has control server permissions.'
        end
        else
        begin
            set @ResultDescripton       = 'No other principal other than internal ones, have control server permissions.'
        end
       
        insert into @finalAssesment
        Select
             [CheckResult]      = @finding_condition_met
            ,[ResultValue]      = @ResultValue
            ,[ResultDescripton] = @ResultDescripton
       
        select * from @finalAssesment
'@
    }

    # check 1
    $reachedInstance = [bool]
    $findingStatus   = "not_a_finding"
    $myCommentList   = @()
    $checkedBy      = "{0} {1}" -f "Check performed by:",$env:USERNAME
    $dateChecked    = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    try{
        $reachedInstance = $true
        $checkResults = Invoke-Command -Session $session -ScriptBlock ${Function:Invoke-UDFSQLCommand} -ArgumentList $SQLCommandParams -ErrorAction Stop
    }catch{
        $reachedInstance = $false
    }
   

    if($reachedInstance -eq $false){
        $findingStatus = "open"
         $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
            $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."

            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($myCommentList -join "`n")
            })
           
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
       
            if($DisplayStatus){
                $PSSTIG.GetFindingInfo(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                })
            }
    }else{
        $myCheckResults = @(
            [pscustomobject]@{Results = $checkResults.Rows.CheckResult ; ResultValue = $checkResults.Rows.ResultValue; ResultDescripton = $checkResults.Rows.ResultDescripton}
        )
   
        if($myCheckResults.Results -eq 1){
            $findingStatus = "open"
        }
   
        if($myCheckResults.Results -eq 0){
            $findingStatus = "not_a_finding"
        }
   
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Remarks:'
        $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescripton, "There is a total of '$($myCheckResults.ResultValue)' accounts that need to be addressed.")
        #$myCommentList += "'$SourceDataFrom' is used to document all sql logins that are memebers of 'sysadmin','securityadmin', or 'serveradmin' roles for instance '$($instanceName)'."

        $adminRoleScript    = $myScripts['script_02']
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $adminRoleScript
        }
   
        $checkResults   = Invoke-Command -Session $session -ScriptBlock ${Function:Invoke-UDFSQLCommand} -ArgumentList $SQLCommandParams
        $myContent      = @(Get-Content -path $SourceDataFrom | ConvertFrom-Csv -Delimiter ",")
        $headingString  = [string]
        $headingsList   = @("RecordID","InstanceName","Memeber","Type","Role","Description")
        $headingString  ='"{0}"' -f ($headingString = $headingsList -join '","')
   
        if(0 -eq [int]$myContent.count){
            Add-Content -Path $SourceDataFrom -Value $headingString
        }
   
        if(0 -eq [int]$myContent.count){
            [int]$recordID = 1
        }else{
            [int]$recordID = [int]$myContent.RecordID[-1]+1
        }
       
        $myEntriesList  = @()
        foreach($accountName in $checkResults){
            $entryString    = [string]
            $myEntry        = @("$recordID","$($accountName.InstanceName)","$($accountName.Member)","$($accountName.Type)","$($accountName.Role)","$($accountName.Description)")
            $entryString    =  '"{0}"'-f ($entryString = $myEntry -join '","')
            $myEntriesList += $entryString
            $recordID       = ($recordID) + 1
        }
   
        $newEntriesList         = $myEntriesList | ConvertFrom-Csv -Header $headingsList
        $myCurrenEntriesTable   = $myContent | Group-Object -Property 'InstanceName' -AsHashTable
   
        $nullDescriptionList    = @()
        $noEntryExistsList      = @()
        $noAccountNameExistList = @()
        foreach($newEntry in $newEntriesList){
            $newEntryInstanceName = $newEntry.InstanceName
            $currentEntriesObject = $myCurrenEntriesTable.$newEntryInstanceName
           
            # are there entries for this hostname?
            $instanceNameEntryExists = [bool]
            if($currentEntriesObject.InstanceName.count -eq 0){
                $instanceNameEntryExists = $false
            }else{
                $instanceNameEntryExists = $true
            }
   
            # if the entry doesnt already exist, then it gets added
            if(-not($instanceNameEntryExists)){
                $myEntry = ('{0},"{1}","{2}","{3}","{4}","{5}"' -f
                    $newEntry.RecordID,
                    $newEntry.InstanceName,
                    $newEntry.Memeber,
                    $newEntry.Type,
                    $newEntry.Role,
                    $newEntry.Description)
                Add-Content -Path $SourceDataFrom -Value $myEntry
                $findingStatus      = "open"
                $noEntryExistsList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
            # is the name of the account in the list?
            $accountNameExists = [bool]
            if(-not($currentEntriesObject.Memeber -contains $newEntry.Memeber)){
                $accountNameExists = $false
            }else{
                $accountNameExists = $true
            }
   
            if( $accountNameExists -eq $false){
                $findingStatus          = "open"
                $noAccountNameExistList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
   
            $currentEntryCheck = $currentEntriesObject |
                Select-Object -Property @('Memeber','Description') |
                Where-Object {$_.Memeber -eq ($newEntry.Memeber)}
   
            $entryDescriptionIsNUll = $currentEntryCheck.Description -match 'NULL'
           
            if($entryDescriptionIsNUll){
                $findingStatus          = "open"
                $nullDescriptionList += [pscustomobject]@{InstanceName = $newEntry.InstanceName ; Memeber = $newEntry.Memeber}
            }
        }
   
        if($findingStatus -eq "open"){
            if($nullDescriptionList.count -gt 0){
                $myCommentList += "All members need to be documented with a description, the following members are missing a description:"
                $myNullMembersList = ($nullDescriptionList | Select-Object -Property Memeber).Memeber
                $myMembersString = @()
                foreach($member in $myNullMembersList){
                    if($member -eq 'sa'){
                        $myMembersString += ("   '{0}' is missing a description. Note: 'sa' accounts need to be renamed and disabled." -f $member)
                    }else{
                        $myMembersString += ("   '{0}' is missing a description." -f $member)
                    }
                }
                $myMembersString = $myMembersString -join "`n"
                $myCommentList += $myMembersString
            }
        }else{
            $myCommentList += "'$SourceDataFrom' is used to document all role memebers for instance'$($instanceName)'."
        }
   
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
   
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214045{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME   = "Invoke-FindingV214045"
    }
    process{
        # if a script is needed, get it
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = "V-214045"#$FindingID
        })

        # instance name is needed
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # sqlcommand params are defined
    # TODO: still cant reference my script from GetSQLQuery
        # manually adding it
        $SQLCommandParams = @{
        DatabaseName    = "master"
        InstanceName    = $instanceName
        Query           = @"
        DECLARE @temp_results TABLE (
        name            varchar(max),
        config_value    varchar(max)
        )

        INSERT INTO @temp_results
        EXEC master.sys.xp_loginconfig 'login mode';

        -- CheckResult  either 1 for a finding 0 for not a finding
        -- ResultValue what value was evaluated
        -- ResultDescripton check description
        select
            case
                when config_value = 'Windows NT Authentication'
                then 0
                else 1
            end as 'CheckResult',
            [ResultValue]       = config_value,
            [ResultDescripton]  = 'using windows only authentication'
        from
        @temp_results
"@
        }

        # sql command is ran
        $invokeParams = @{
            Session = $Session
            ScriptBlock = ${Function:Invoke-UDFSQLCommand}
            ArgumentList  = $SQLCommandParams
            ErrorAction  = 'Stop'
        }

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{Results = $checkResults.Rows.CheckResult ; ResultValue = $checkResults.Rows.ResultValue; ResultDescripton = $checkResults.Rows.ResultDescripton}
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescripton, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescripton, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214042{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-FindingV214045"
        $FINDING_DESCRIPTION    = 'The SQL Server Browser service must be disabled unless specifically required and approved'
    }
    process{
        $invokeParams = @{
            Session         = $Session
            ScriptBlock     = {Get-Service -Name 'SQLBrowser' -ErrorAction Stop}
            ErrorAction     = 'Stop'
        }

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
        $reachedInstance = [bool]
        try{
            $reachedInstance  = $true
            $checkResults = Invoke-Command @invokeParams
       
        }catch{
            $reachedInstance  = $false
            $checkResults = $Error[0]
        }
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += 'Remarks:'
            $myCommentList += "Was unable to perform check on Host '$HostName', validate that the host is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $checkResultAssessed = [pscustomobject]@{
                CheckResult         = [int]
                ResultValue         = [string]
                ResultDescripton    = [string]
            }

           
            $checkResultAssessed.CheckResult = switch(($checkResults.Status)){
                "Running"{ 1}
                "Stopped"{ 0 }
            }

            $checkResultAssessed.ResultValue        = "SQL Browser is currently '{0}'." -f $checkResults.Status
            $checkResultAssessed.ResultDescripton   = "SQL admins and authorized users to discover database instances over the network"

       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($checkResultAssessed.CheckResult -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $checkResultAssessed.ResultDescripton, "")
            }
       
            if($checkResultAssessed.CheckResult -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $checkResultAssessed.ResultDescripton, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214043{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding214043"
        $FINDING_DESCRIPTION    = "SQL Server Replication Xps feature must be disabled, unless specifically required and approved"

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214044{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding214044"
        $FINDING_DESCRIPTION    = "If the SQL Server Browser Service is specifically required and approved, SQL instances must be hidden."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214041{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding214041"
        $FINDING_DESCRIPTION    = "SQL Server External Scripts Enabled feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214040{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
       
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Remote Data Archive feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214039{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Allow Polybase Export feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214038{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Hadoop Connectivity feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214037{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Remote Access feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214036{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server User Options feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214035{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Ole Automation Procedures feature must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214034{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Filestream must be disabled, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214033{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server execute permissions to access the registry must be revoked, unless specifically required and approved."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214032{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server Service Broker endpoint must utilize AES encryption."

        $reachedHost        = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $pwshScriptBlock = {
            # 0 -> TLS is is enabled and not a finding
            # 1 _> TLS is not enabled and a finding
            $enableManualOverride           = $false
            $value                          = 0
            $openResult_Description        = "TLS 1.2 is not enaled."
            $notafinding_ResultDescription  = "TLS 1.2 is enaled."
       
            $checkResults = [pscustomobject]@{
                CheckResults        = [int]
                ResultValue         = [int]
                ResultDescription   = [string]
            }
           
            if($enableManualOverride){
                switch($value){
                    1   {
                        $checkResults.CheckResults = 1
                        $checkResults.ResultValue  = 0
                        $checkResults.ResultDescription = $openResult_Description
                    }
                    0   {
                        $checkResults.CheckResults = 0
                        $checkResults.ResultValue  = 1
                        $checkResults.ResultDescription = $notafinding_ResultDescription
                    }
                }
            }
       
            if($enableManualOverride -eq $false){
                $checkCompleted = [bool]
                try{
                    $checkCompleted             = $true
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -ErrorAction stop) | Out-Null
                    $checkResults.ResultValue = 0
                }catch{
                    $checkCompleted  = $false
                    $checkResults.ResultValue = 1
                }
           
                $checkResults.CheckResults = switch($checkCompleted){
                    $false  { 1 }
                    $true   { 0 }
                }
           
                if($checkResults.CheckResults -eq 1){
                    $checkResults.ResultDescription = $openResult_Description
                }
                if($checkResults.CheckResults -eq 0){
                    $checkResults.ResultDescription = $notafinding_ResultDescription
                }
            }
           $checkResults
        }
        $invokeParams = @{
            Session         = $Session
            ScriptBlock     = $pwshScriptBlock
            ErrorAction     = 'Stop'
        }
       
        try{
            $reachedHost = $true
            $checkResults = (Invoke-Command @invokeParams) | Select-Object -Property * -ExcludeProperty ("RunSpaceID","PSComputerName")
        }catch{
            $reachedHost = $false
        }
       
        # if you cant reach instance
        if($reachedHost -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on host '$HostName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.CheckResults
                    ResultValue         = $checkResults.ResultValue
                    ResultDescription   = $checkResults.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME

   
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ' '
                $myCommentList += $myCheckResults.ResultDescription
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += $myCheckResults.ResultDescription
                $myCommentList += ' '
                $myCommentList += "When TLS 1.2 is enabled, relying solely on SQL AES encryption becomes redundant because"
                $myCommentList += "TLS 1.2 already provides robust encryption and authentication for secure communication between SQL Server instances and applications ."
                $myCommentList += "Adding an additional layer of AES encryption would unnecessarily complicate the setup and management without significantly enhancing security."
               
            }
        }
    }
    end{
 
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214031{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server Mirroring endpoint must utilize AES encryption."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214030{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Execution of startup stored procedures must be restricted to necessary cases only."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214029{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server default account [sa] must have its name changed."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214028{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "The SQL Server default account [sa] must be disabled."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214027{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "SQL Server must configure SQL Server Usage and Error Reporting Auditing."

        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })
       
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
            }
            # sql command is ran
            $invokeParams = @{
                Session = $Session
                ScriptBlock = ${Function:Invoke-UDFSQLCommand}
                ArgumentList  = $SQLCommandParams
                ErrorAction  = 'Stop'
            }
   
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.Rows.CheckResults
                    ResultValue         = $checkResults.Rows.CheckValue
                    ResultDescription    = $checkResults.Rows.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214026{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Customer experience improvement program (CEIP) not used in enviornment."

        $reachedInstance    = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $productScriptBlock = {
            # 0 -> TLS is is enabled and not a finding
            # 1 -> TLS is not enabled and a finding
            $enableManualOverride           = $false
            $value                          = 0
            $openResult_Description        = "One or More instances are participating in the customer experience improvement program (CEIP)."
            $notafinding_ResultDescription  = "No instances are participating in the customer experience improvement program (CEIP)."
       
            $checkResults = [pscustomobject]@{
                CheckResults        = [int]
                ResultValue         = @()
                ResultDescription   = [string]
            }
            $instancesInstalledList = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server').InstalledInstances
            if($enableManualOverride){
                switch($value){
                    1   {
                        $checkResults.CheckResults = 1
                        $checkResults.ResultValue  += $instancesInstalledList
                        $checkResults.ResultDescription = $openResult_Description
                    }
                    0   {
                        $checkResults.CheckResults = 0
                        $checkResults.ResultValue  += $instancesInstalledList
                        $checkResults.ResultDescription = $notafinding_ResultDescription
                    }
                }
            }
            if($enableManualOverride -eq $false){
                $myHostName = HostName
                $instanceProductConfigurationList  = @()
                foreach($i in $instancesInstalledList) {
                    $product = (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL').$i
                    $productParameters = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft SQL Server\$product\CPE\"
           
                    $instanceName = [string]
                    if(-not($myHostName -eq $i)){
                        $instanceName = ("{0}\{1}" -f $myHostName,$i)
                    }else{
                        $instanceName = $i
                    }
                    $instanceProductConfigurationList  += [pscustomobject]@{
                        HostName                = $myHostName
                        Instancename            = $instanceName
                        CustomerFeedback        = $productParameters.CustomerFeedback
                        EnableErrorReporting    = $productParameters.EnableErrorReporting    
                    }
                }
                foreach($instProduct in $instancesInstalledList){
                    if(($instProduct.CustomerFeedback -or $instProduct.EnableErrorReporting) -eq 0){
                        $checkResults.CheckResults = 1
                        $checkResults.ResultDescription = $openResult_Description
                    }else{
                        checkResults.CheckResults = 0
                        $checkResults.ResultDescription = $notafinding_ResultDescription
                    }
                }
                $checkResults.ResultValue = $instanceProductConfigurationList
            }
            $checkResults
        }
        $invokeParams = @{
            Session = $Session
            ScriptBlock = $productScriptBlock
            ArgumentList  = $SQLCommandParams
            ErrorAction  = 'Stop'
        }
       
        try{
            $reachedInstance = $true
            $checkResults = Invoke-Command @invokeParams | Select-Object -Property * -ExcludeProperty ("PSComputerName","RunspaceId")
        }catch{
            $reachedInstance = $false
        }
       
        # if you cant reach instance
        if($reachedInstance -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on host '$HostName', validate that the host is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.CheckResults
                    ResultValue         = $checkResults.ResultValue
                    ResultDescription    = $checkResults.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += " "
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            $aggregatedComment = @()
            foreach($entry in $checkResults.ResultValue){
                $aggregatedComment += "On host '{0}, instance {1} has CustomerFeedback set to {2}, and Enabled ErrorReporting set to {3}'" -f
                    $entry.HostName,
                    $entry.Instancename,
                    $entry.CustomerFeedback,
                    $entry.EnableErrorReporting
            }

            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
                $myCommentList += $aggregatedComment
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += ("{0}`n{1} " -f $myCheckResults.ResultDescription, "")
                $myCommentList += $aggregatedComment
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214025{
    param(
        [string]$HostName,
        [string]$FindingID,
        [string]$CheckListName,
        [switch]$DisplayStatus,
        [string]$DocumentationFolderPath
       
    )
    begin{
        $DocumentationFileName      = ("\{0}SQLArchivedLogging.json" -f $CheckListName)
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "The system SQL Server must off-load audit data to a separate log management facility."


        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $checkResults = [pscustomobject]@{
            CheckResults        = [int]
            ResultValue         = @()
            ResultDescription   = [string]
        }

        $DefaultSettings = @{
            IsNearRealTime = $true
            StorageLabel = "\HostName\SomeLocation"
            ArchiveInterval = "weekly"
            DirectlyWritesToArchive = $false
            HasContinousConnection = $true
        }
        $docExists = $PSSTIG.PSUTILITIES.GetUtilitySettingsTable(@{Label = $CheckListname })
        if($docExists -eq 0){
            $SQLLogsTable = @{}
            $SQLLogsTable.Add($CheckListname,@(@{
                IsNearRealTime          = $DefaultSettings.IsNearRealTime
                StorageLabel            = $DefaultSettings.StorageLabel
                DirectlyWritesToArchive = $DefaultSettings.DirectlyWritesToArchive
                ArchiveInterval         = $DefaultSettings.ArchiveInterval
                HasContinousConnection  = $DefaultSettings.HasContinousConnection
            }))
            $PSSTIG.PSUTILITIES.CacheConfiguration(@{
                Configuration = $SQLLogsTable
                Label       = $CheckListname
                FolderPath  = $DocumentationFolderPath
                FileName    = $DocumentationFileName
                Overwrite   = $false
            })
        }
        $myDocumentation = $PSSTIG.PSUTILITIES.ReadCache(@{
            Label = $CheckListname
        })
       
        $HashContinousConnection = $myDocumentation.$CheckListname.HasContinousConnection
        $DirectlyWritesToArchive = $myDocumentation.$CheckListname.DirectlyWritesToArchive
       
        $myCommentList += $checkedBy
        $myCommentList += $dateChecked
        $myCommentList += ' '
        $myCommentList += 'Description:'
        $myCommentList += $FINDING_DESCRIPTION
        $myCommentList += " "
        $myCommentList += 'Remarks:'
        $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME

        if(($HashContinousConnection -eq $true )-and ($DirectlyWritesToArchive -eq $false)){
            $checkResults.CheckResults = 1
            $myCommentList += "There is a continouse connection, but the logs are not written directly to the archive location."
        }else{
            $checkResults.CheckResults = 0
            $myCommentList += "There is a continouse connection, and the logs are  written directly to the archive location."
        }
       
     
        $ArchiveInterval = $myDocumentation.$CheckListname.ArchiveInterval
        if(($HashContinousConnection -eq $false )-and ($ArchiveInterval -notmatch "weekly")){
            $checkResults.CheckResults = 1
            $myCommentList += "There is a intermittent connection, but the logs are not written weekly."
        }else{
            $checkResults.CheckResults = 0
            $myCommentList += "There is a intermittent connection, and the logs are written weekly."
        }


        if($checkResults.CheckResults -eq 1){
            $findingStatus = "open"
            $myCommentList += ("{0}`n{1} " -f $FINDING_DESCRIPTION, "")
            $myCommentList += $aggregatedComment
        }
   
        if($checkResults.CheckResults -eq 0){
            $findingStatus = "not_a_finding"
            $myCommentList += ("{0}`n{1} " -f $FINDING_DESCRIPTION, "")
            $myCommentList += $aggregatedComment
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        $updatedTargetData = [bool]
        try{
            $updatedTargetData = $true
            #Get-TargetData -CheckListName $CheckListName -Session $Session -ErrorAction Stop
        }catch{
            $updatedTargetData = $false
        }
       
        if($updatedTargetData -eq $false){
            $PSSTIG.PSUTILITIES.DisplayMessage(@{
                Message = ($PSSTIG.myMessage -f $FUNCTION_NAME, "Unable to update targetdata checklist '$($CheckListName).'")
                Category = "feedback"
                Type = "warning"
            })
        }
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214024{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not implementing NIST FIPS 140-2 or 140-3 validated cryptographic modules"
            NotafindingResultDescription    = "SQL Server is implementing NIST FIPS 140-2 or 140-3 validated cryptographic modules"
            EnableManualOverride            = $false
            Value                           = 0
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "Customer experience improvement program (CEIP) not used in enviornment."
        }
        # checkedBy                       = "{0} {1}" -f "Check performed by:",$env:USERNAME
        # dateChecked                     = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')

        # this check itself with all its properties as defined in the argumentlist hashtable
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # when enabled, results are manually set on the checklist file
            if($argumentList.enableManualOverride){
                switch($value){
                    # in this block you can simulate the check is an open finding
                    1   {
                        $Check.Result      = 1
                        $Check.Value       = "[Manually set finding result to open]"
                        $Check.Description = $argumentList.OpenResultDescription
                    }

                    # in this block you can simuate the check is not a finding
                    0   {
                        $Check.Result      = 0
                        $Check.Value       = "[Manually set finding result to not_a_finding]"
                        $Check.Description = $argumentList.NotafindingResultDescription
                    }
                }
            }
            # when disabled, results are set from the check done
            if($argumentList.enableManualOverride -eq $false){
                $findingData = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
                $Check.Value = $findingData.Enabled
                # when returned true, its not a finding
                if($findingData.Enabled -eq 1){
                    $Check.Result      = 0
                    $Check.Description = $argumentList.NotafindingResultDescription
                }
                else{
                    $Check.Result      = 1
                    $Check.Description = $argumentList.OpenResultDescription
                }
            }

            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{
        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
       
        # if you cant reach instance
        if($establishedSession -eq $false){
            $findingStatus = "open"
            $myComments  += ' '
            $myComments  += 'Remarks:'
            $myComments  += "Was unable to perform check on host '$HostName', validate that the host is running and is accessible."
        }else{
            $myComments    += ' '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $ArgumentList.FUNCTION_NAME
       
            if($myResult.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
       
            if($myResult.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
        }
    }
    end{
        # here we update the checklist itself
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ("{0}" -f($myComments -join "`n"))
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })

        # here we display as needed
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214021{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records for all direct access to the database(s)."
            NotafindingResultDescription    = "SQL Server is generating audit records for all direct access to the database(s)."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records for all direct access to the database(s)."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.Result
            $Check.Value = $findingData.Rows.Value
            $Check.Description = $findingData.Rows.Description

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Description, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Description, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214020{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records for all direct access to the database(s)."
            NotafindingResultDescription    = "SQL Server is generating audit records for all direct access to the database(s)."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records for all direct access to the database(s)."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_result
            if($Check.Result -eq 0){
                $Check.Description = $argumentList.OpenResultDescription
            }else{
                $Check.Description = $argumentList.NotafindingResultDescription
            }
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Description, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Description, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214018{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when concurrent logons/connections by the same user from different workstations occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when concurrent logons/connections by the same user from different workstations occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when concurrent logons/connections by the same user from different workstations occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214017{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records showing starting and ending time for user access to the database(s)."
            NotafindingResultDescription    = "SQL Server is generating audit records showing starting and ending time for user access to the database(s)."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records showing starting and ending time for user access to the database(s)."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214016{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when unsuccessful attempts to execute privileged activities or other system-level access occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when unsuccessful attempts to execute privileged activities or other system-level access occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214015{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records for all privileged activities or other system-level access."
            NotafindingResultDescription    = "SQL Server is generating audit records for all privileged activities or other system-level access."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records for all privileged activities or other system-level access."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214014{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful logons or connection attempts occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when successful and unsuccessful logons or connection attempts occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful logons or connection attempts occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214012{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur."
            NotafindingResultDescription    = "SQL Server is  generating audit records when successful and unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214010{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to delete security objects occur."
            NotafindingResultDescription    = "SQL Server is  generating audit records when successful and unsuccessful attempts to delete security objects occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to delete security objects occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214008{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to delete privileges/permissions occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when successful and unsuccessful attempts to delete privileges/permissions occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to delete privileges/permissions occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214006{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when successful and unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214004{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to modify security objects occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when successful and unsuccessful attempts to modify security objects occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to modify security objects occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214002{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to modify privileges/permissions occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when successful and unsuccessful attempts to modify privileges/permissions occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to modify privileges/permissions occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214000{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to add privileges/permissions occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when successful and unsuccessful attempts to add privileges/permissions occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to add privileges/permissions occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213998{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not generating audit records when successful and unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur."
            NotafindingResultDescription    = "SQL Server is generating audit records when successful and unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must generate audit records when successful and unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams
            $Check.Result = $findingData.Rows.check_result
            $Check.Value = $findingData.Rows.check_value
            $Check.Description = $findingData.Rows.result_type

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213994{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "Security-relevant software updates to SQL Server is not being installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs)."
            NotafindingResultDescription    = "Security-relevant software updates to SQL Server is being installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs)."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "Security-relevant software updates to SQL Server must be installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs)."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }
            $this_kb = '13.0.5103.6'
            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams

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
            $status = [int]
            if(-not($datetime -gt $date_window)){
                $check_patch_value = "the last time the patch was check was '$($datetime)', in compliance. {0}."
                $status = 0
            }else{
                $check_patch_value = "the last time the patch was check was '$($datetime)' out of compliance, check every '21' days. {0}"
                $status = 1
            }

            ($findingData.rows.check_result) -match '(.*) (\(KB.*\)) - (.*) \(.*\)'
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

            $Check.Result = $status
            $Check.Value = $Final_check_value
            $Check.Description = $check_kb_version_value

       
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213929{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [string]$FolderPath,
        [string]$FileName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server Instance has no limit of connections per session, or ncurrent sessions go over the limited set value."
            NotafindingResultDescription    = "SQL Server Instance has a limit of connections per session, and no current sessions go over the limited set value."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams

            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "


            return @{
                Data     = $findingData
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }


        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $GetDocumentParams = @{
                FolderPath = $FolderPath
                FileName   = $FileName
            }
            $SourcePath = (Get-DocumentSource @GetDocumentParams)
            $ReadDocumentParams = @{
                DocumentSourcePath = $SourcePath
            }
            $myDocData = Read-DocumentSource @ReadDocumentParams
            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }
            $instanceEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}
            if($null -eq $instanceEntry){
                $DefaultData = $myDocData.Schema.DefaultValues
                if($myDocData.TotalEntries -eq 0){
                    [int]$lastRecID =$DefaultData.RecID
                }else{
                    [int]$lastRecID = ($myDocData.data)[-1].RecID
                }
               
                $InsertItem = [pscustomobject]@{
                    # use the last ID of an existsing entry
                    RecID                               = ($lastRecID + 1)
                    HostName                            = $HostName
                    InstanceName                        = $instanceName
                    MaxConcurrentSessionByAccountType   = $DefaultData.MaxConcurrentSessionByAccountType
                    Set                                 = $DefaultData.Set
                    DateSet                             = $DefaultData.DateSet
                    SetBy                               = $DefaultData.SetBy
                    LastChecked                         = $DefaultData.LastChecked
                }
                $InsertString = '"{0}"' -f(@(
                $InsertItem.RecID,
                $InsertItem.HostName,
                $InsertItem.InstanceName,
                $InsertItem.MaxConcurrentSessionByAccountType
                $InsertItem.Set
                $InsertItem.DateSet
                $InsertItem.SetBy
                $InsertItem.LastChecked) -join '","')
                Add-Content -path $SourcePath -Value $InsertString
            }
            $myDocData = Read-DocumentSource @ReadDocumentParams
            $instanceEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}
            if($instanceEntry.Set -eq "notSet"){
                $Check.Result = 1
                $check.Value = $instanceEntry.MaxConcurrentSessionByAccountType
            }else{
                $Check.Result   = 0
                $Check.Value    = $instanceEntry.MaxConcurrentSessionByAccountType
            }
            $AccountsList  = @()
            foreach($row in $myResult.rows){
                $AccountsList+= [PSCustomObject]@{
                    HostName                            = $HostName
                    InstanceName                        = $instanceName
                    MaxConcurrentSessionByAccountType   = $row.session_count
                    AccountType                         = $row.login_name
                }
            }
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
            $myComments += "At the time of this check the following accounts have the total connections per account running on $instanceName."
            foreach($account in $AccountsList){
                if($Check.Value -eq 0){
                    $myComments += "The {0} account on {1}, has a total of {2}, and with no limit set, this is a finding." -f
                        $account.AccountType,
                        $instanceName,
                        $account.MaxConcurrentSessionByAccountType
                }else{
                    if($check.Value -lt $acount.MaxConcurrentSessionByAccountType){
                        $myComments += "The {0} account on {1}, has a total of {2} session, and with a limit set of {3}, this is a finding due to the account having more sessions then the set limit." -f
                            $account.AccountType,
                            $instanceName,
                            $account.MaxConcurrentSessionByAccountType,
                            $Check.Value
           
                        $check.Result = 1
                    }else{
                        $myComments += "The {0} account on {1}, has a total of {2} session, and with a limit set of {3}, this is not a finding due an account having less sessions then the set limit." -f
                        $account.AccountType,
                        $instanceName,
                        $account.MaxConcurrentSessionByAccountType,
                        $Check.Value
           
                    $check.Result = 0
                    }
                }
            }
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $Check.Value, "")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
# this is a good example of a powershell scriptblock only function
Function Invoke-Finding213969{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not using NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations."
            NotafindingResultDescription    = "SQL Server is using NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations."
            EnableManualOverride            = $false
            Value                           = 0
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations."
        }
        # checkedBy                       = "{0} {1}" -f "Check performed by:",$env:USERNAME
        # dateChecked                     = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')

        # this check itself with all its properties as defined in the argumentlist hashtable
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # when enabled, results are manually set on the checklist file
            if($argumentList.enableManualOverride){
                switch($value){
                    # in this block you can simulate the check is an open finding
                    1   {
                        $Check.Result      = 1
                        $Check.Value       = "[Manually set finding result to open]"
                        $Check.Description = $argumentList.OpenResultDescription
                    }

                    # in this block you can simuate the check is not a finding
                    0   {
                        $Check.Result      = 0
                        $Check.Value       = "[Manually set finding result to not_a_finding]"
                        $Check.Description = $argumentList.NotafindingResultDescription
                    }
                }
            }
            # when disabled, results are set from the check done
            if($argumentList.enableManualOverride -eq $false){
                $findingData = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
                $Check.Value = $findingData
                # when returned true, its not a finding
                if($findingData.Enabled -eq 1){
                    $Check.Result      = 0
                    $Check.Description = $argumentList.NotafindingResultDescription
                }
                else{
                    $Check.Result      = 1
                    $Check.Description = $argumentList.OpenResultDescription
                }
            }

            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{
        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
       
        # if you cant reach instance
        if($establishedSession -eq $false){
            $findingStatus = "open"
            $myComments  += ' '
            $myComments  += 'Remarks:'
            $myComments  += "Was unable to perform check on host '$HostName', validate that the host is running and is accessible."
        }else{
            $myComments    += ' '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $ArgumentList.FUNCTION_NAME
       
            if($myResult.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
       
            if($myResult.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
        }
    }
    end{
        # here we update the checklist itself
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ("{0}" -f($myComments -join "`n"))
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })

        # here we display as needed
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213968{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "SQL Server is not using NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.`n Validate SQL Server is using TDE or not aswell"
            NotafindingResultDescription    = "SQL Server is using NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.`n Validate SQL Server is using TDE or not aswell"
            EnableManualOverride            = $false
            Value                           = 0
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must enforce authorized access to all PKI private keys stored/utilized by SQL Server."
        }
        # checkedBy                       = "{0} {1}" -f "Check performed by:",$env:USERNAME
        # dateChecked                     = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')

        # this check itself with all its properties as defined in the argumentlist hashtable
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # when enabled, results are manually set on the checklist file
            if($argumentList.enableManualOverride){
                switch($value){
                    # in this block you can simulate the check is an open finding
                    1   {
                        $Check.Result      = 1
                        $Check.Value       = "[Manually set finding result to open]"
                        $Check.Description = $argumentList.OpenResultDescription
                    }

                    # in this block you can simuate the check is not a finding
                    0   {
                        $Check.Result      = 0
                        $Check.Value       = "[Manually set finding result to not_a_finding]"
                        $Check.Description = $argumentList.NotafindingResultDescription
                    }
                }
            }
            # when disabled, results are set from the check done
            if($argumentList.enableManualOverride -eq $false){
                $findingData = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
                $Check.Value = $findingData
                # when returned true, its not a finding
                if($findingData.Enabled -eq 1){
                    $Check.Result      = 0
                    $Check.Description = $argumentList.NotafindingResultDescription
                }
                else{
                    $Check.Result      = 1
                    $Check.Description = $argumentList.OpenResultDescription
                }
            }

            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "
            $argumentList.MyCommentList += $Check.Description


            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{
        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
       
        # if you cant reach instance
        if($establishedSession -eq $false){
            $findingStatus = "open"
            $myComments  += ' '
            $myComments  += 'Remarks:'
            $myComments  += "Was unable to perform check on host '$HostName', validate that the host is running and is accessible."
        }else{
            $myComments    += ' '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $ArgumentList.FUNCTION_NAME
       
            if($myResult.Result -eq 1){
                $findingStatus = "open"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
       
            if($myResult.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += ("{0}`n{1} " -f $myResult.Description,"")
            }
        }
    }
    end{
        # here we update the checklist itself
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ("{0}" -f($myComments -join "`n"))
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })

        # here we display as needed
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213967{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{
        $FUNCTION_NAME          = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
        $FINDING_DESCRIPTION    = "Confidentiality of information during transmission is controlled through the use of an approved TLS version."

        $reachedHost        = [bool]
        $findingStatus      = "not_a_finding"
        $myCommentList      = @()
        $checkedBy          = "{0} {1}" -f "Check performed by:",$env:USERNAME
        $dateChecked        = "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
    }
    process{
        $pwshScriptBlock = {
            # 0 -> TLS is is enabled and not a finding
            # 1 _> TLS is not enabled and a finding
            $enableManualOverride           = $false
            $value                          = 0
            $openResult_Description        = "TLS 1.2 is not enaled."
            $notafinding_ResultDescription  = "TLS 1.2 is enaled."
       
            $checkResults = [pscustomobject]@{
                CheckResults        = [int]
                ResultValue         = [int]
                ResultDescription   = [string]
            }
           
            if($enableManualOverride){
                switch($value){
                    1   {
                        $checkResults.CheckResults = 1
                        $checkResults.ResultValue  = 0
                        $checkResults.ResultDescription = $openResult_Description
                    }
                    0   {
                        $checkResults.CheckResults = 0
                        $checkResults.ResultValue  = 1
                        $checkResults.ResultDescription = $notafinding_ResultDescription
                    }
                }
            }
       
            if($enableManualOverride -eq $false){
                $checkCompleted = [bool]
                try{
                    $checkCompleted             = $true
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -ErrorAction stop) | Out-Null
                    $checkResults.ResultValue = 0
                }catch{
                    $checkCompleted  = $false
                    $checkResults.ResultValue = 1
                }
           
                $checkResults.CheckResults = switch($checkCompleted){
                    $false  { 1 }
                    $true   { 0 }
                }
           
                if($checkResults.CheckResults -eq 1){
                    $checkResults.ResultDescription = $openResult_Description
                }
                if($checkResults.CheckResults -eq 0){
                    $checkResults.ResultDescription = $notafinding_ResultDescription
                }
            }
           $checkResults
        }
        $invokeParams = @{
            Session         = $Session
            ScriptBlock     = $pwshScriptBlock
            ErrorAction     = 'Stop'
        }
       
        try{
            $reachedHost = $true
            $checkResults = (Invoke-Command @invokeParams) | Select-Object -Property * -ExcludeProperty ("RunSpaceID","PSComputerName")
        }catch{
            $reachedHost = $false
        }
       
        # if you cant reach instance
        if($reachedHost -eq $false){
            $findingStatus = "open"
             $myCommentList += $checkedBy
                $myCommentList += $dateChecked
                $myCommentList += ' '
                $myCommentList += 'Remarks:'
                $myCommentList += "Was unable to perform check on host '$HostName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myCommentList -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $myCheckResults = @(
                [pscustomobject]@{
                    Results             = $checkResults.CheckResults
                    ResultValue         = $checkResults.ResultValue
                    ResultDescription   = $checkResults.ResultDescription
                }
            )
       
            $myCommentList += $checkedBy
            $myCommentList += $dateChecked
            $myCommentList += ' '
            $myCommentList += 'Description:'
            $myCommentList += $FINDING_DESCRIPTION
            $myCommentList += ' '
            $myCommentList += 'Remarks:'
            $myCommentList += "Check was performed by powershell function {0}" -f $FUNCTION_NAME

   
            if($myCheckResults.Results -eq 1){
                $findingStatus = "open"
                $myCommentList += ' '
                $myCommentList += $myCheckResults.ResultDescription
            }
       
            if($myCheckResults.Results -eq 0){
                $findingStatus = "not_a_finding"
                $myCommentList += $myCheckResults.ResultDescription
                $myCommentList += ' '
                $myCommentList += "When TLS 1.2 is enabled, relying solely on SQL AES encryption becomes redundant because"
                $myCommentList += "TLS 1.2 already provides robust encryption and authentication for secure communication between SQL Server instances and applications ."
                $myCommentList += "Adding an additional layer of AES encryption would unnecessarily complicate the setup and management without significantly enhancing security."
               
            }
        }
    }
    end{
 
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myCommentList -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213964{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "If DBMS authentication is employed, if SQL Server Logins are  being used,DoD standards for password complexity and lifetime, need to be enforced."
            NotafindingResultDescription    = "If DBMS authentication is not employed, if SQL Server Logins are not being used, no password enforcment is required."
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "If DBMS authentication using passwords is employed, SQL Server must enforce the DoD standards for password complexity and lifetime."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }

            # wen disabled, results are set from the check done
            $findingData = @{}
            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData.Add($script,(Invoke-Command @mySQLCommandParams))
            }
            $script_01Result = $findingData.script_01
            if($script_01Result.Rows."Authentication Mode" -eq "Windows Authentication"){
                $Check.Result       = 0
                $Check.Value        = $script_01Result.Rows."Authentication Mode"
                $Check.Description  = "This is not a finding on the grounds that the instance is using windows authentication"

                $argumentList.MyCommentList += $check.Description
            }else{
                $Check.Value = "Using MixMode Login"
                $argumentList.MyCommentList += "Instance is not using Windows authentication, in which case, the ExpirationChecked and PolicyChecked settings need to be evaluated."
                $script2Data = @()
                $script_02Result = $findingData.script_02
                foreach($result in $script_02Result.Rows){
                    $script2Data +=[pscustomobject]@{
                        Name                = $result.name
                        ExpirationChecked   = $result.is_expiration_checked
                        PolicyChecked       = $result.is_policy_checked
                    }
                }

                foreach($entry in $script2Data){
                    if(($entry.ExpirationChecked -eq $false) -or ($entry.PolicyChecked -eq $false)){
                        $Check.Result = 1
                        if($entry.ExpirationChecked -eq $false){
                            $argumentList.MyCommentList += "    This is a finding  due to '$($entry.Name)' not having set the Expiration policy."
                        }
                        if($entry.PolicyChecked -eq $false){

                            $argumentList.MyCommentList += "    This is a finding due to '$($entry.Name)' not having set the PolicyChecked setting."
                        }
                    }
                   
                    if(($entry.ExpirationChecked -eq $false) -and ($entry.PolicyChecked -eq $false)){
                        $Check.Result = 1
                        $argumentList.MyCommentList += "    This is a finding due to '$($entry.Name)' not having set the Expiration policy."
                        $argumentList.MyCommentList += "    This is a finding due to '$($entry.Name)' not having set the PolicyChecked setting."
                    }
                }
            }
            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $null
        }

        $ArgumentList.Add("Scripts",$myScripts)
        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                    Description   = $myResult.Description
                }
            )

            $myComments += '    '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += (" ")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213934{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
            }

            # wen disabled, results are set from the check done
            $findingData = @{}
            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData.Add($script,(Invoke-Command @mySQLCommandParams))
            }

            foreach($result in $findingData.keys){
                $Check.Value = $findingData.$result.check_value
                if($findingData.$result.check_result -eq 0){
                    $Check.result = 0
                    $argumentList.MyCommentList += $check.value
                }else{
                    $Check.Result = 1
                    $argumentList.MyCommentList += $check.value
                }
            }
            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $null
        }

        $ArgumentList.Add("Scripts",$myScripts)
        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                }
            )

            $myComments += '    '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += (" ")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213995{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must be able to generate audit records when successful and unsuccessful attempts to access security objects occur."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
            }

            # wen disabled, results are set from the check done
            $findingData = @{}
            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData.Add($script,(Invoke-Command @mySQLCommandParams))
            }

            foreach($result in $findingData.keys){
                $Check.Value = $findingData.$result.check_value
                if($findingData.$result.check_result -eq 0){
                    $Check.result = 0
                    $argumentList.MyCommentList += $check.value
                }else{
                    $Check.Result = 1
                    $argumentList.MyCommentList += $check.value
                }
            }
            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $null
        }

        $ArgumentList.Add("Scripts",$myScripts)
        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value

                }
            )

            $myComments += '    '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
       
            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += (" ")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213993{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [string]$FolderPath,
        [string]$FileName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #region  - user set values
            OpenResultDescription           = "the features currently installed are different from the previous version running."
            NotafindingResultDescription    = "There are some new features that differ from the ones documented."
           
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "When updates are applied to SQL Server software, any software components that have been replaced or made unnecessary must be removed."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            # wen disabled, results are set from the check done
            $mySQLCommandParams = @{
                ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                ArgumentList    = $argumentList.SQLCOmmandParams
                ErrorAction     = "Stop"
            }

            $findingData = Invoke-Command @mySQLCommandParams

            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "


            return @{
                Data     = $findingData
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = ("{0}" -f ($myScripts[$FindingID] -join "`n"))
        }

        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }


        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }

        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $GetDocumentParams = @{
                FolderPath = $FolderPath
                FileName   = $FileName
            }
            $SourcePath = (Get-DocumentSource @GetDocumentParams)
            $ReadDocumentParams = @{
                DocumentSourcePath = $SourcePath
            }
            $myDocData = Read-DocumentSource @ReadDocumentParams
            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
                Description   = [string]
            }
            $instanceEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}
            if($null -eq $instanceEntry){
                $DefaultData = $myDocData.Schema.DefaultValues
                if($myDocData.TotalEntries -eq 0){
                    [int]$lastRecID =$DefaultData.RecID
                }else{
                    [int]$lastRecID = ($myDocData.data)[-1].RecID
                }
               
                $InsertItem = [pscustomobject]@{
                    # use the last ID of an existsing entry
                    RecID                               = ($lastRecID + 1)
                    HostName                            = $HostName
                    InstanceName                        = $instanceName
                    "SQL Server Version"                = $myResult.rows."SQL Server Version"
                    "Service Pack Level"                = $myResult.rows."Service Pack Level"
                    "Edition"                           = $myResult.rows."Engine Edition"
                    "Engine Edition"                    = $myResult.rows."Engine Edition"
                    "Is Clustered"                      = $myResult.rows."Is Clustered"
                    "Full-Text Installed"               = $myResult.rows."Full-Text Installed"  
                    "Integrated Security Only"              = $myResult.rows."Integrated Security Only"  
                    "Always On Availability Groups Enabled"= $myResult.rows."Always On Availability Groups Enabled"
                    "PolyBase Installed"                    = $myResult.rows."PolyBase Installed"  
                    "Replication Installed"                 = $myResult.rows."Replication Installed"  
                }

                $InsertString = '"{0}"' -f(@(
                    $InsertItem.RecID
                    $InsertItem.HostName
                    $InsertItem.InstanceName
                    $InsertItem."SQL Server Version"
                    $InsertItem."Service Pack Level"
                    $InsertItem."Edition"
                    $InsertItem."Engine Edition"
                    $InsertItem."Is Clustered"
                    $InsertItem."Full-Text Installed"
                    $InsertItem."Integrated Security Only"
                    $InsertItem."Always On Availability Groups Enabled"
                    $InsertItem."PolyBase Installed"
                    $InsertItem."Replication Installed") -join '","')
                Add-Content -path $SourcePath -Value $InsertString
            }
            $myDocData = Read-DocumentSource @ReadDocumentParams
            $instanceEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}
            $featuresList  = @()
            $Check.Result   = 0
            if($instanceEntry."Full-Text Installed" -ne $myResult.rows."Full-Text Installed"){
                $Check.Result = 1
                $Check.Value    = "Current SQL Server version has feature not present in the last"
                $featuresList  += "Full-Text Installed"
            }else{
                $Check.Value    = "Current SQL Server version has feature the same as in the last"
             
            }
            if($instanceEntry."Is Clustered" -ne $myResult.rows."Is Clustered"){
                $Check.Result = 1
                $Check.Value    = "Current SQL Server version has feature not present in the last"
                $featuresList  += "Is Clustered"
            }else{
                $Check.Value    = "Current SQL Server version has feature the same as in the last"
               
            }
            if($instanceEntry."Integrated Security Only" -ne $myResult.rows."Integrated Security Only"){
                $Check.Result = 1
                $Check.Value    = "Current SQL Server version has feature not present in the last"
                $featuresList  += "Integrated Security Only"
            }else{
                $Check.Value    = "Current SQL Server version has feature the same as in the last"
             
            }
            if($instanceEntry."Always On Availability Groups Enabled" -ne $myResult.rows."Always On Availability Groups Enabled"){
                $Check.Result = 1
                $Check.Value    = "Current SQL Server version has feature not present in the last"
                $featuresList  += "Always On Availability Groups Enabled"
            }else{
                $Check.Value    = "Current SQL Server version has feature the same as in the last"
               
            }
            if($instanceEntry."PolyBase Installed" -ne $myResult.rows."PolyBase Installed"){
                $Check.Result = 1
                $Check.Value    = "Current SQL Server version has feature not present in the last"
                $featuresList  += "PolyBase Installed"
            }else{
                $Check.Value    = "Current SQL Server version has feature the same as in the last"
               
            }
            if($instanceEntry."Replication Installed" -ne $myResult.rows."Replication Installed"){
                $Check.Result = 1
                $Check.Value    = "Current SQL Server version has feature not present in the last"
                $featuresList  += "Replication Installed"
            }else{
                $Check.Value    = "Current SQL Server version has feature the same as in the last"
               
            }
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
            $myComments += "At the time of this check the following features differ from the previous version  $instanceName."
            $myComments += ("{0}" -f ($featuresList -join "`n"))
            if($Check.Result -eq 1){
                $findingStatus = "open"
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213930{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [string]$FolderPath,
        [string]$FileName,
        [switch]$DisplayStatus
    )
    begin{

        # instance name comes from the checklist name
        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $FUNCTION_NAME   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        $ArgumentList   = @{
            SQLInvokeCommand    = $null
            SQLCommandParams    = @{}
            Scripts             = @{}
            MyCommentList       = @(
                "{0} {1}" -f "Check performed by:",$env:USERNAME,
                "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff'),
                " ",
                "Description: "
            )
        }
        $ArgumentList.SQLInvokeCommand  = ${Function:Invoke-UDFSQLCommand}
        $ArgumentList.Scripts           = $PSSTIG.GetSQLQuery(@{FindingID = $FindingID})
        $ArgumentList.SQLCommandParams  = @{DatabaseName = "master" ; InstanceName = $instanceName ; Query = $null}
        $ScriptBlock = {
            param($argumentList)

            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = @()
            }

            $findingData = @{}
            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData.Add($script,(Invoke-Command @mySQLCommandParams))
            }
            $Check.Result = $findingData.script_01.Rows.result

            # evaluate results here
            # check can be either 0 for widows auth, or mixed mode
             if($Check.Result -eq 0){
                $argumentList.MyCommentList += "This instance uses Windows only authentication."
            }else{
                $argumentList.MyCommentList += "This instance uses Mixed Mode authentication."
            }

            # only when its not windows auth, do we evaluate the script 2 results
            if($Check.Result -eq 1){
                # if there are no sql logins, its not a finding
                if($findingData.script_02.rows.result -eq 0){
                    $argumentList.MyCommentList += "Instance uses Mixed Mode, but ther are no sql logins enabled:"
                }else{
                # if there are  sql logins, its  a finding
                    $argumentList.MyCommentList += "Instance uses Mixed Mode, and there are some sql logins:"
                    foreach($row in $findingData.script_02.rows){
                        $Check.value += [pscustomobject]@{
                            name        = $row.Name
                            isDisabled  = $row.Is_disabled
                        }
                    }
                }
            }
            return @{
                Data     = $Check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        try{
            $establishedSession = $true
            $Finding            = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
   
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
           #$script:myResult
           
           # if($myResult.Result -eq 1 -and $myResult)
            # if there is sql logins
            if(($myResult.Value).count -gt 0){
                $GetDocumentParams = @{
                    FolderPath = $FolderPath
                    FileName   = $FileName
                }
                $SourcePath = (Get-DocumentSource @GetDocumentParams)
                $ReadDocumentParams = @{
                    DocumentSourcePath = $SourcePath
                }
                $myDocData = Read-DocumentSource @ReadDocumentParams
                $Check = [pscustomobject]@{
                    Result        = [int]
                    Value         = $null
                }
                $instanceEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}

                 # do this when there is no data in the datafile
                if($null -eq $instanceEntry){
                    $DefaultData = $myDocData.Schema.DefaultValues
                    if($myDocData.TotalEntries -eq 0){
                        [int]$lastRecID =$DefaultData.RecID
                    }else{
                        [int]$lastRecID = ($myDocData.data)[-1].RecID
                    }
                    foreach($account in $myResult.Value){
                        $lastRecID = $lastRecID + 1
                        $InsertItem = [pscustomobject]@{
                            # use the last ID of an existsing entry
                            RecID           = $lastRecID
                            HostName        = $HostName
                            InstanceName    = $instanceName
                            Account         = $account.name
                            isApproved      = $DefaultData.isApproved
                            isDisabled      = $account.isDisabled
                            Description     = $DefaultData.Description
                        }
                        $InsertString = '"{0}"' -f(@(
                            $InsertItem.RecID
                            $InsertItem.HostName
                            $InsertItem.InstanceName
                            $InsertItem.account
                            $InsertItem.isApproved
                            $InsertItem.isDisabled
                            $InsertItem.Description) -join '","')
                        Add-Content -path $SourcePath -Value $InsertString
                       
                    }
                }
                $myDocData      = Read-DocumentSource @ReadDocumentParams
                $instanceEntry  = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}
                $myComments += "Account has to both be documented and approved for it to not be a finding:"
                foreach($entry in $instanceEntry){
                    if((($entry.isApproved -eq 'NULL') -or ($entry.isApproved -eq $false)) -or  (($entry.isDocumented -eq 'NULL') -or ($entry.isDocumented -eq $false))){
                        if($entry.isApproved -eq 'NULL') {
                            $myComments += "    '$($entry.account)' is not documented as approved or not approved. Update '$FileName' with isApproved status"
                        }
                        if($entry.isApproved -eq $false) {
                            $myComments += "    '$($entry.account)' is not not approved. Account needs to be removed before its considered not a finding"
                        }
                        if($entry.Description -eq 'NULL'){
                            $myComments += "    '$($entry.account)' need to be documented with a description of its usage. Update '$FileName' with Description status"
                        }
                        if($entry.Description -eq $false){
                            $myComments += "    '$($entry.account)' need to be documented with a description of its usage. Update '$FileName' with Description status"
                        }
                        $Check.Result = 1
                    }
                   
                    # acount has to both be documented and approved for it to not be a finding
                    if(($entry.isApproved -eq $true) -and ($entry.isDocumented -eq $true)){
                        if($entry.isApproved -eq $true) {
                            $myComments += "    '$($entry.account)' is documented as approved."
                        }
                        if($entry.Description -eq $true){
                            $myComments += "    '$($entry.account)' is documented with a description of its usage."
                        }
                        $Check.Result = 0
                    }
                }
            }
           
           
            $myComments += ' '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $FUNCTION_NAME
            if($myResult.Result -eq 1){
                $findingStatus = "open"
            }
       
            if($myResult.Result -eq 0){
                $findingStatus = "not_a_finding"
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213935{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the instance."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData = (Invoke-Command @mySQLCommandParams)
            }
           
            $sqlList = @()
            foreach($sql in $findingData.rows){
                $sqlList += [pscustomobject]@{
                    Result = $sql.result
                    Value = $sql.value
                }
            }

            $check = [pscustomobject]@{
                result = [int]
                value  = @()
            }

            # only when there is results returned from sql do we run this
            if(($sqlList | Group-Object -Property Result -AsHashTable) -eq 1){
                $argumentList.MyCommentList += "The following account(s), have been identified as being a windows login or a windows group login ending with '$'"
                $argumentList.MyCommentList += "Any account returned need to be validated to be a computer account:"

                # get the login name from each result
                foreach($unknownAccnt in $sqlList){
                    $accntName = $unknownAccnt.value
                    if(($accntName) -match '(.*)\\(.*)(\$)'){
                        $name = $matches[2]
                        $ldapResult = (([ADSISearcher]"(&(ObjectCategory=Computer)(Name=$name))").FindAll())

                        # no results is not a finding, or 0
                        if($null -eq $ldapResult){
                            $check.result = 0
                        }else{
                            $check.result = 1
                            $check.value  += $accntName
                        }
                    }
                }
            }else{
                $argumentList.MyCommentList += "No account(s), have been identified as being a windows login or a windows group login ending with '$'"
                $check.result = 0
            }
            return @{
                Data     = $check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $null
        }

        $ArgumentList.Add("Scripts",$myScripts)
        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult  = $Finding.Data
        $myComments = $Finding.Comments

       
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check = @(
                [pscustomobject]@{
                    Result        = $myResult.Result
                    Value         = $myResult.Value
                }
            )

            $myComments += '    '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME

            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += (" ")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213991{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$FolderPath,
        [string]$FileName,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must maintain a separate execution domain for each executing process."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData = (Invoke-Command @mySQLCommandParams)
            }
           
            $sqlList = @()
            foreach($sql in $findingData.rows){
                $sqlList += [pscustomobject]@{
                    Result = $sql.result
                }
            }

            $check = [pscustomobject]@{
                result = [int]
            }

            # only when there is results returned from sql do we run this
            if(($sqlList.result) -eq 1){
                $argumentList.MyCommentList += "CLR assemblies on this instance are enabled. They need to be checked and deemed required."
                $check.result = 1

            }else{
                $argumentList.MyCommentList += "CLR assemblies on this instance are not enabled"
                $check.result = 0
            }
            return @{
                Data     = $check
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $null
        }

        $ArgumentList.Add("Scripts",$myScripts)
        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult  = $Finding.Data
        $myComments = $Finding.Comments
       
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            if(($myResult.result) -eq 1){
                $GetDocumentParams = @{
                    FolderPath = $FolderPath
                    FileName   = $FileName
                }
                $SourcePath = (Get-DocumentSource @GetDocumentParams)
                $ReadDocumentParams = @{
                    DocumentSourcePath = $SourcePath
                }
                $myDocData = Read-DocumentSource @ReadDocumentParams
                $Check = [pscustomobject]@{
                    Result        = [int]
                    Value         = $null
                }
                $instanceEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}

                 # do this when there is no data in the datafile
                if($null -eq $instanceEntry){
                    $DefaultData = $myDocData.Schema.DefaultValues
                    if($myDocData.TotalEntries -eq 0){
                        [int]$lastRecID =$DefaultData.RecID
                    }else{
                        [int]$lastRecID = ($myDocData.data)[-1].RecID
                    }
                    $lastRecID = $lastRecID + 1
                    $InsertItem = [pscustomobject]@{
                        # use the last ID of an existsing entry
                        RecID           = $lastRecID
                        HostName        = $HostName
                        InstanceName    = $instanceName
                        isApproved      = $DefaultData.isApproved
                        Description     = $DefaultData.Description
                    }
                    $InsertString = '"{0}"' -f(@(
                        $InsertItem.RecID
                        $InsertItem.HostName
                        $InsertItem.InstanceName
                        $InsertItem.isApproved
                        $InsertItem.isDisabled
                        $InsertItem.Description) -join '","')
                    Add-Content -path $SourcePath -Value $InsertString
                }
                $myDocData      = Read-DocumentSource @ReadDocumentParams
                $instanceEntry  = $myDocData.Data | Select-Object -Property * | Where-Object {$_.InstanceName -eq $instanceName}
                if($instanceEntry.isApproved -eq $false){
                    $myComments += "CLR settings is not approved on this instance"
                    $myComments += "updated  '$SourcePath' with appropriate approval"
                    $myResult.Result = 1
                }else{
                    $myComments     += "CLR settings is approved on this instance"
                    $myCommentList  += "updated  '$SourcePath' with appropriate approval."
                    if($instanceEntry.Description -match ''){
                        $myComments += "While not considered 'open' when CLR is approved"
                        $myComments += "please updated  '$SourcePath'"
                        $myComments += "with a description as to why its required as well on this instance."
                    }else{
                        $myComments += ""
                        $myComments += "Justification:"
                        $myComments += $instanceEntry.Description
                    }
                    $myResult.Result = 0
                }
            }
        }
           
        $myComments += ' '
        $myComments += 'Remarks:'
        $myComments += "Check was performed by powershell function {0}" -f $ArgumentList.FUNCTION_NAME
        if($myResult.Result -eq 1){
            $findingStatus = "open"
            $myComments += (" ")
        }

        if($myResult.Result -eq 0){
            $findingStatus = "not_a_finding"
            $myComments += (" ")
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213992{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$FolderPath,
        [string]$FileName,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }
        else{ $establishedSession = $null }

        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must maintain a separate execution domain for each executing process."
        }


        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            #If any services are configured with the same service account or are configured with an account that is not documented and authorized, this is a finding.
            $serviceNames = (Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE Name like '%SQL%'") | Select-Object Name,StartName
            $filteredService = @()
            foreach($service in $serviceNames){
                if($service.name -notlike 'SQLTELEMETRY*'){
                    if(($service.name -ne "SQLBrowser")){
                        #if($service.StartName -ne 'LocalSystem'){
                        $filteredService += [pscustomobject]@{
                            DomainName = $env:USERDNSDOMAIN
                            Name = $service.Name
                            Account = $service.StartName
                            }
                        #}
                    }
                }
            }

            $Check = [pscustomobject]@{
                Result = [int]
            }
            $Services = ($filteredService | Select-Object -Property * | Where-Object {$_.name -notlike "MSSQLFDLauncher*"})
            $ServiceGrouping = $Services | Group-Object -Property Account
            $check.Result = 0
            foreach($grouping in $ServiceGrouping){
                if($grouping.count -gt 1){
                    $check.Result = 1
                }
            }

            if($Check.Result -eq 1){
                $argumentList.MyCommentList += "More than one of the SQL services or SQL Agent share the same service account."
                                foreach($service in $Services){
                    $argumentList.MyCommentList += "{0} {1}" -f $service.Name, $service.Account
                }

            }else{
                $argumentList.MyCommentList += "All SQL services or SQL Agent on the host use different service account."
                foreach($service in $Services){
                    $argumentList.MyCommentList += "{0} {1}" -f $service.Name, $service.Account
                }
            }
               
           return @{
                Check       = $Check
                Data        =  $Services
                Comments    = $argumentList.MyCommentList
            }

        }
    }
    process{
        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         =$Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult  = $Finding.Data
        $myComments = $Finding.Comments
   
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $GetDocumentParams = @{
                FolderPath = $FolderPath
                FileName   = $FileName
            }
            $SourcePath = (Get-DocumentSource @GetDocumentParams)
            $ReadDocumentParams = @{
                DocumentSourcePath = $SourcePath
            }
            $myDocData = Read-DocumentSource @ReadDocumentParams
            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
            }
            $domainName = $myResult.DomainName | Select-Object -First 1

            # look in the documentation list for all host, not this host, in the given
            $HostEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.hostname -eq $HostName -and $_.DomainName -eq $domainName}
            if($null -eq $HostEntry){
                foreach($account in $myResult){
                    $DefaultData = $myDocData.Schema.DefaultValues
                    if($myDocData.TotalEntries -eq 0){
                        [int]$lastRecID =$DefaultData.RecID
                    }else{
                        [int]$lastRecID = ($myDocData.data)[-1].RecID
                    }
                    $lastRecID = $lastRecID + 1
                    $InsertItem = [pscustomobject]@{
                        # use the last ID of an existsing entry
                        RecID       = $lastRecID
                        DomainName  = $domainName
                        HostName    = $HostName
                        Name        = $account.Name
                        Account     = $account.Account
                    }
                    $InsertString = '"{0}"' -f(@(
                        $InsertItem.RecID
                        $InsertItem.DomainName
                        $InsertItem.HostName
                        $InsertItem.Name
                        $InsertItem.Account) -join '","')
                    Add-Content -path $SourcePath -Value $InsertString
                    $myDocData  = Read-DocumentSource @ReadDocumentParams    
                }
            }
            $HostEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.hostname -ne $hostname -and $_.DomainName -eq $domainName}
            # see if there is shared account across host
            $accountGrouping  = $HostEntry | Group-Object -Property Account
            $hostnames = ($HostEntry.Hostname | Group-Object).name

           
            $findingTable = @()
            $Check.Result = 0
            foreach($accntGroup in $accountGrouping){
                if($accntGroup.count -gt 1){
                    $Check.Result = 1
                    foreach($hostof in $accntGroup.Group){
                        $findingTable += [pscustomObject]@{
                            HostName        = $hostof.HostName
                            ServiceName     = $hostof.name
                            SharedAccount   = $accntGroup.Name
                        }
                    }
                }
            }

            if($Check.Result -eq 1){
                $myComments += ""
                $myComments += "The following SQL Service Account and/or SQL Agent Account on host '$hostname' is being on other hosts within the $domainName domain:"
                foreach($sharedAccount in $findingTable){
                    $myComments += "On host '{0}' the service '{1}' is using the same account '{2}' being used on {3}" -f
                        $sharedAccount.HostName,
                        $sharedAccount.ServiceName,
                        $sharedAccount.SharedAccount,
                        $hostName
                }
            }
            if($Check.Result -eq 0){
                $myComments += ""
                $myComments += "No SQL Service Account or SQL Agent Account on host '$hostname' is being used on any of the following host:"
                foreach($checkedHost in $hostnames){
                    $myComments += $checkedHost
                }
            }

            $myComments += ' '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $ArgumentList.FUNCTION_NAME
            if(($Check.Result -eq 1) -or ($Finding.Check.Result -eq 1)){
               
                $findingStatus = "open"
                $myComments += (" ")
            }

            if(($Check.Result -eq 0) -and ($Finding.Check.Result -eq 0)){
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213990{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$FolderPath,
        [string]$FileName,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }else{ $establishedSession = $null }

        # the instance name is derived from the $checklistName
        $instanceNameList   = $CheckListName -split '_'
        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            InstanceName                    = $instanceNameList[1]
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must maintain a separate execution domain for each executing process."
        }


        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            
            $IntanceNetInfo = @()
            $myHostName     = HOSTNAME
            $instanceName   = $argumentList.InstanceName
            $root           = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server" 
            $registry       = Get-ChildItem -Path  $root| Where-Object {$_.Name -like ('*MSSQL*.{0}' -f $instanceName)}
            $propertiesPath = $registry.PSPath

            $netProperties = Get-ChildItem  "$propertiesPath\MSSQLServer\SuperSocketNetLib\Tcp"
            foreach($interface in $netProperties){
                $interfaceProperties = Get-ItemProperty -path  $interface.pspath

                # is the static port being used?
                if($interfaceProperties.TcpPort.length -eq 0){
                    $usingStatic    = $false
                    $staticPort     = $null
                }else{
                    $usingStatic    = $true
                    $staticPort     = $interfaceProperties.TcpPort
                }

                # if blank, dynamic ports are disabled
                if($interfaceProperties.TcpDynamicPorts.length -eq 0){
                    $usingDynamic    = $false
                    $dynamicPort     = $null
                }

                # if 0 dynamic port is enabled
                if($interfaceProperties.TcpDynamicPorts -eq 0){
                    $usingDynamic    = $true
                    $dynamicPort     = $interfaceProperties.TcpDynamicPorts
                }

                $IntanceNetInfo += [pscustomobject]@{
                    HostName        = $myHostName
                    InstanceName    = $instanceName
                    Interface       = $interface.PSChildName
                    UsingStaticPort = $usingStatic 
                    StaticPort      = $staticPort
                    UsingDynamic    = $usingDynamic
                    DynamicPort     = $dynamicPort
                }
            }
            
           return @{
                Data        = ($IntanceNetInfo | Select-Object -Property * | Where-Object {$_.interface -eq 'IPAll'})
                Comments    = $argumentList.MyCommentList
            }
        }
    }
    process{
        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult  = $Finding.Data
        $myComments =  $Finding.Comments

        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $GetDocumentParams = @{
                FolderPath = $FolderPath
                FileName   = $FileName
            }
            $SourcePath = (Get-DocumentSource @GetDocumentParams)
            $ReadDocumentParams = @{
                DocumentSourcePath = $SourcePath
            }
            $myDocData = Read-DocumentSource @ReadDocumentParams
            $Check = [pscustomobject]@{
                Result        = [int]
                Value         = $null
            }
   
            # look in the documentation list for all host, not this host, in the given
            $HostEntry = $myDocData.Data | Select-Object -Property * | Where-Object {$_.hostname -eq $HostName -and $_.instanceName -eq $instanceNameList[1]}
            if($null -eq $HostEntry){
                $DefaultData = $myDocData.Schema.DefaultValues
                if($myDocData.TotalEntries -eq 0){
                    [int]$lastRecID =$DefaultData.RecID
                }else{
                    [int]$lastRecID = ($myDocData.data)[-1].RecID
                }

                $lastRecID = $lastRecID + 1
                $InsertItem = [pscustomobject]@{
                    # use the last ID of an existsing entry
                    RecID           = $lastRecID
                    HostName        = $myResult.HostName
                    InstanceName    = $myResult.InstanceName
                    Interface       = $myResult.Interface
                    UsingStaticPort = $myResult.UsingStaticPort
                    StaticPort      = $myResult.StaticPort
                    UsingDynamic    = $myResult.UsingDynamic
                    DynamicPort     = $myResult.DynamicPort
                    isApproved      = $DefaultData.isApproved
                    ApprovedPort    = $DefaultData.ApprovedPort
                }
                
  
                $InsertString = '"{0}"' -f(@(
                    $InsertItem.RecID
                    $InsertItem.HostName
                    $InsertItem.InstanceName
                    $InsertItem.Interface
                    $InsertItem.UsingStaticPort
                    $InsertItem.StaticPort
                    $InsertItem.UsingDynamic
                    $InsertItem.DynamicPort
                    $InsertItem.isApproved
                    $InsertItem.ApprovedPort) -join '","')
                Add-Content -path $SourcePath -Value $InsertString
                $myDocData  = Read-DocumentSource @ReadDocumentParams    
            }

            $myDocData = $myDocData.Data | Select-Object -Property * | Where-Object {$_.hostname -eq $myResult.hostname -and $_.instanceName -eq $myResult.InstanceName}

            
            if($myDocData.isApproved -eq 'Static'){
                if($myResult.UsingStaticPort){
                    $myApprovedPort = $myResult.StaticPort
                    $Check.Result = 0
                    $myComments += "Approved to use static port, port setting is static."
                }else{
                    $myApprovedPort = $myResult.StaticPort
                    $Check.Result = 1
                    $myComments += "Approved to use static port, port setting is not static."
                }
            }
            if($myDocData.isApproved -eq 'Dynamic'){
                if($myResult.UsingDynamic){
                    $myApprovedPort = $myResult.DynamicPort
                    $Check.Result = 0
                    $myComments += "Approved to use dynamic port, port setting is dynamic."
                }else{
                    $myApprovedPort = $myResult.DynamicPort
                    $Check.Result = 1
                    $myComments += "Approved to use dynamic port, port setting is not dynamic."
                }
            }

            if($myDocData.ApprovedPort -eq $myApprovedPort){
                $Check.Result = 0
                $myComments += "Current port is the one that is approved."
            }else{
                $Check.Result = 1
                $myComments += "Current port is not the one that is approved."
            }
            $myComments += ' '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $ArgumentList.FUNCTION_NAME
            if($Check.Result -eq 1){
               
                $findingStatus = "open"
                $myComments += (" ")
            }

            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213965{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$FolderPath,
        [string]$FileName,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }else{ $establishedSession = $null }

        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            # wen disabled, results are set from the check done
  
            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData =  Invoke-Command @mySQLCommandParams
            }

       
            return @{
                Data     = $findingData
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $null
        }

        $ArgumentList.Add("Scripts",$myScripts)
        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check =[pscustomobject]@{Result        =[int]}


            $containdDBJson = ($myResult.rows | Select-Object -Property * | Where-Object {$_.CheckType -eq 'ContainedDatabases'}).Result
            $containdDBs = ($containdDBJson | ConvertFrom-Json).result

            $myComments += "{0}" -f ($containdDBs.comments -join "`n")
            if($containdDBs.value -eq 0){
                $Check.Result = 0
            }else{
                $Check.Result = 1
            }

            $ContainedUsersJson = ($myResult.rows | Select-Object -Property * | Where-Object {$_.CheckType -eq 'ContainedUsers'}).Result
            $ContainedUsers = ($ContainedUsersJson | ConvertFrom-Json).result

            $myComments += "{0}" -f ($ContainedUsers.comments -join "`n")
            if($ContainedUsers.value -eq 0){
                $Check.result = 0
            }else{

                $dbMaxLen       = ($ContainedUsers.users.DatabaseName | ForEach-Object({ $_.Length }) | Measure-Object -Maximum).Maximum
                $userMaxLen     = ($ContainedUsers.users.UserName | ForEach-Object({ $_.Length }) | Measure-Object -Maximum).Maximum
                $headingDBLen   = "DatabaseName".Length
                $UserNameLen    = "UserName".Length

                $len1 = switch($dbMaxLen -ge $headingDBLen){
                    $true {$dbMaxLen}
                    $false{$headingDBLen}
                } 
                $len2 = switch($userMaxLen -ge $UserNameLen){
                    $true {$userMaxLen}
                    $false{$UserNameLen}
                }

                $valStringList = @()
                $valStringList += "{0}" -f (@("| DatabaseName |"," UserName |"," AuthenticationType |") -join "")
                $valStringList +='| '+'-'*(6+($len1 + $len2 + ("AuthenticationType".Length)))+ ' |'
                foreach($entry in $ContainedUsers.users){
                    $bufferLenth = $len1 - $entry.DatabaseName.Length
                    $val1 = "| $($entry.DatabaseName+(' '*($bufferLenth))) |"
                    $bufferLenth = $len2 - $entry.UserName.Length
                    $val2 = " $($entry.UserName+(' '*($bufferLenth))) |"
                    $bufferLenth = ("AuthenticationType".Length) - 1 
                    $val3 = " $([string]($entry.AuthenticationType)+[string](' '*($bufferLenth))) |"

                    $valStringList +="{0}" -f (@($val1,$val2,$val3) -join '')
                }
                $myComments += $valStringList
                
                ($len1 - $headingList[0].Length) + 2
                $Check.result = 1
            }

            $myComments += '    '
            $myComments += 'Remarks:'
            $myComments += "Check was performed by powershell function {0}" -f $argumentlist.FUNCTION_NAME
            


            if($Check.Result -eq 1){
                $findingStatus = "open"
                $myComments += (" ")
            }
       
            if($Check.Result -eq 0){
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213956{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$FolderPath,
        [string]$FileName,
        [string]$CheckListName,
        [switch]$DisplayStatus
    )
    begin{

        # when this switch is true, the function will work in a remote scope, false to work in local scope
        $REMOTE_FUNCTION    = $true
        if($REMOTE_FUNCTION){ $establishedSession = [bool] }else{ $establishedSession = $null }

        $ArgumentList = @{
            #endregion - user set values
            MyCommentList                   = @()
            FindingStatus                   = [string]
            FUNCTION_NAME                   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]
            FINDING_DESCRIPTION             = "SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration."
        }
        $myScripts      = $PSSTIG.GetSQLQuery(@{
            FindingID = $FindingID
        })

        $instanceNameList   = $CheckListName -split '_'
        $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

        # this is what happens in the session scope
        $ScriptBlock = {
            param($argumentList)
            $argumentList.MyCommentList += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $argumentList.MyCommentList += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $argumentList.MyCommentList += " "
            $argumentList.MyCommentList += "Description: "

            # wen disabled, results are set from the check done
  
            foreach($script in $argumentList.Scripts.keys){
                $argumentList.SQLCOmmandParams.Query = ("{0}" -f ($argumentList.Scripts.$script -join "`n"))

                $mySQLCommandParams = @{
                    ScriptBlock     = [scriptblock]::Create($argumentList.SQLInvokeCommand)
                    ArgumentList    = $argumentList.SQLCOmmandParams
                    ErrorAction     = "Stop"
                }
                $findingData =  Invoke-Command @mySQLCommandParams
            }

            $Listing = @()
            $Listing += [pscustomobject]@{
                Listing             = "Microsoft SQL Server 2016"
                StartDate           = "Jun 1, 2016"
                MainStreamEndData   = "Jul 13, 2021"
                ExtendedDate        = "Jul 14, 2026"
            }
            $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
            $installedSoftware = Get-ItemProperty -Path $registryPath |
            Where-Object {
                $_.DisplayName -and $_.DisplayName -ne "Security Update" -and
                $_.DisplayName -like '*SQL*' -and $_.DisplayName -notlike '*Security Update*'
            } |
            Select-Object DisplayName, DisplayVersion |
            Sort-Object -Property DisplayName, DisplayVersion -Unique
            $resultsTable = @{
                InstalledSoftware   = $installedSoftware
                SQLVersionCheck     = $findingData
            }
            return @{
                Data     = $resultsTable
                Comments = $argumentList.MyCommentList
            }
        }
    }
    process{

        # sql command parameters get defined
        $SQLCommandParams = @{
            DatabaseName    = "master"
            InstanceName    = $instanceName
            Query           = $null
        }

        $ArgumentList.Add("Scripts",$myScripts)
        # sql command parameters get added to the argument list
        $ArgumentList.Add("SQLCOmmandParams",$SQLCommandParams)
        $ArgumentList.Add("SQLInvokeCommand",${Function:Invoke-UDFSQLCommand})

        # when running remotly, session is included in the invocation
        if($REMOTE_FUNCTION){
            $invokeParams = @{
                Session         = $Session#(Get-PSSession -Name $InstanceLevelParam.HostName)
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $argumentList
                ErrorAction     = 'Stop'
            }
        }else{
            $invokeParams = @{
                ScriptBlock     = $ScriptBlock
                ArgumentList    = $ArgumentList
                ErrorAction     = 'Stop'
            }
        }

        # it either will succeed or fail
        #$invokeParams.ArgumentList
        try{
            $establishedSession = $true
            $Finding = Invoke-Command @invokeParams
        }catch{
            $establishedSession = $false
        }
       
        $myResult   = $Finding.Data
        $myComments = $Finding.Comments
        $myResult.SQLVersionCheck =  $myResult.SQLVersionCheck.Rows.Result    | ConvertFrom-Json
        #if you cant reach instance
        if($establishedSession -eq $false){
            $myComments = @()
            $findingStatus = "open"
                $myComments += "{0} {1}" -f "Check performed by:",$env:USERNAME
                $myComments += "{0} {1}" -f "Check was done on :",(get-date).ToString('yyyy-MM-dd HH:mm:ss.fff')
                $myComments += ' '
                $myComments += 'Remarks:'
                $myComments += "Was unable to perform check on instance '$instanceName', validate that the instance is running and is accessible."
       
                $PSSTIG.UpdateComment(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Comment         = ($myComments -join "`n")
                })
               
                $PSSTIG.UpdateStatus(@{
                    CheckListName   = $CheckListName
                    FindingID       = $FindingID
                    Status          = $findingStatus
                })
           
                if($DisplayStatus){
                    $PSSTIG.GetFindingInfo(@{
                        CheckListName   = $CheckListName
                        FindingID       = $FindingID
                    })
                }
        }else{
            $Check =[pscustomobject]@{Result =[int]}
            
            foreach($installedItem in $myResult.InstalledSoftware ){
                $productSQL = ($installedItem  | Select-Object -Property *  |
                    Where-Object {$_.DisplayName -like "Microsoft SQL Server * (64-bit)"})
                if($null -ne $productSQL){
                    $installedItem.DisplayVersion = $myResult.SQLVersionCheck.ProductVersion
                }
       
            }

            # initalize document data
            $GetDocumentParams  = @{FolderPath = $FolderPath ; FileName   = $FileName}
            $SourcePath         = (Get-DocumentSource @GetDocumentParams)
            $ReadDocumentParams = @{DocumentSourcePath = $SourcePath}
            $myDocData          = Read-DocumentSource @ReadDocumentParams

            # check if the data file has any data for this check
            $hasData = $myDocData.Data | Select-Object -Property * | Where-Object {$_.HostName -eq $HostName -and $_.instanceName -eq $instanceName}

            # when no data is present, load results in
            if($null -eq $hasData){

                # get the default data properties for the schema
                $DefaultData = $myDocData.Schema.DefaultValues

                # if the document has no entries
                if($myDocData.TotalEntries -eq 0){

                    # seed the record id, starting the default value
                    [int]$lastRecID =$DefaultData.RecID
                }else{

                    # otherwise use the last record entry value
                    [int]$lastRecID = ($myDocData.data)[-1].RecID
                }

                # each record gets inserted
                foreach($item in $myResult.InstalledSoftware){
                    $lastRecID  = $lastRecID + 1
                    $InsertItem = [pscustomobject]@{
                        RecID           = $lastRecID
                        HostName        = $HostName
                        InstanceName    = $instanceName
                        DisplayName     = $item.DisplayName
                        DisplayVersion  = $item.DisplayVersion
                        isApproved      = $DefaultData.isApproved
                    }
                    $InsertString = '"{0}"' -f(@(
                    $InsertItem.RecID
                    $InsertItem.HostName
                    $InsertItem.InstanceName
                    $InsertItem.DisplayName
                    $InsertItem.DisplayVersion
                    $InsertItem.isApproved) -join '","')
                    Add-Content -path $SourcePath -Value $InsertString
                }
                # data gets reloaded
                $myDocData = Read-DocumentSource @ReadDocumentParams
            }

            $myDocData = $myDocData.Data | Select-Object -Property * | Where-Object {$_.hostname -eq $HostName -and $_.instanceName -eq $InstanceName -and $_.isApproved -eq 'False'}
           
            #   check is considered a finding when anything returned is not approved.
            #   this will always be the case for new software.
            if($myDocData.count -gt 0){
                $Check.Result = 1
                $findingStatus = "open"
                $myComments += (" ")
            }

            if($myDocData.count -eq 0){
                $Check.Result = 0
                $findingStatus = "not_a_finding"
                $myComments += (" ")
            }
        }
    }
    end{
        $PSSTIG.UpdateComment(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Comment         = ($myComments -join "`n")
        })
       
        $PSSTIG.UpdateStatus(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
            Status          = $findingStatus
        })
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213954{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [boolean]$SkipNonFinding = $true,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }
            $comments  = @()
        }
    }
    process{
        if(-not($skip)){
            # handle failed connection to the instance
            try{
                $SQLQueryResult = Invoke-PSSQL @{
                    Session             =   $Sessions[0]
                    SQLScriptFolder     =   ".\PSSTIG\Private\SQLScripts"
                    SQLScriptFile       =   $FindingID
                    ConnectionParams    = @{
                        InstanceName    =   $instanceName
                        DatabaseName    =   "Master"
                    }
                }
            }catch{
                
                # the function will stop if there is an error with the sql command
                Write-Error -message $Error[0]
            }

            $check = (($SQLQueryResult.rows.Results)| ConvertFrom-Json).Result
            
            # comment are being added to array
            $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
            $comments += "{0}" -f ' '
            $comments += "{0}" -f "Remarks:"
            $comments += "{0}" -f $check.comments
            
            # set finding status
            $findingStatus = switch($check.value){
                0       {'not_a_finding'}
                1       {'open'}
                default {'not_reviewed'}
            }
        }
    }
    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding213966{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [boolean]$SkipNonFinding = $true,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        if(-not($skip)){
            # handle failed connection to the instance
            try{
                $SQLQueryResult = Invoke-PSSQL @{
                    Session             =   $Sessions[0]
                    SQLScriptFolder     =   ".\PSSTIG\Private\SQLScripts"
                    SQLScriptFile       =   $FindingID
                    ConnectionParams    = @{
                        InstanceName    =   $instanceName
                        DatabaseName    =   "Master"
                    }
                }
            }catch{
                
                # the function will stop if there is an error with the sql command
                Write-Error -message $Error[0]
            }

            $check = (($SQLQueryResult.rows.Results)| ConvertFrom-Json).Result
            
            # comment are being added to array
            $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
            $comments += "{0}" -f ' '
            $comments += "{0}" -f "Remarks:"
            $comments += "{0}" -f $check.comments
            
            # set finding status
            $findingStatus = switch($check.value){
                0       {'not_a_finding'}
                1       {'open'}
                default {'not_reviewed'}
            }
        }
    }
    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
Function Invoke-Finding214046{
    param(
        [string]$HostName,
        [string]$FindingID,
        [psobject]$Session,
        [string]$CheckListName,
        [boolean]$SkipNonFinding = $true,
        [switch]$DisplayStatus
    )
    begin{
        $functionName   = "Invoke-Finding{0}" -f ($FindingID.Split('-'))[-1]

        # get the checklistdata, initalize a comments array, and define the funciton name
        $lastCheck      = $PSSTIG.GetFindingData(@{
            CheckListName   = $CheckListName
            FindingID       = $FindingID
        })
        
        # by default, if the last status is not a finding, the check is skipped
        if(($lastCheck.Status -eq 'not_a_finding') -and ($SkipNonFinding -eq $true)){
            write-host 'check was previously not_a_finding, was skipped' -ForegroundColor Yellow
            $skip = $true
        }else{
            write-host "check status was previously $($lastCheck.status)" -ForegroundColor Yellow
            $skip = $false
        }

        if(-not($skip)){
            # the current finding status is the last finding status
            $findingStatus  = $lastCheck.status
            
            # instance names are defined off the checklistname
            $instanceNameList   = $CheckListName -split '_'
            $instanceName       = "{0}\{1}" -f $instanceNameList[0],$instanceNameList[1]

            # it's not a named instance
            if($instanceName -match '(.*)\\$'){
                $instanceName = ($instanceName -split '\\')[0]
            }else{
                $instanceName = ($instanceName -split '\\')[-1]
            }
            
            $comments  = @()
        }
    }
    process{
        if(-not($skip)){
            $check = @{
                value = 2
                comments = @(
                    "The requirement emphasizes obscuring feedback of authentication information (e.g., displaying asterisks for passwords).",
                    "While DBAs can enforce security policies within the database, they do not control the user interface or feedback mechanisms.",
                    "The presentation layer (UI) handles feedback to users during authentication (e.g., displaying asterisks or other obfuscation techniques).",
                    "DBAs are not involved in UI design or user interaction, so they cannot directly influence how feedback is presented.",
                    "Therefore, the responsibility for implementing secure feedback mechanisms lies with UI designers, developers, and front-end engineers."
                )
            }
            
            # comment are being added to array
            $comments += "{0} {1}" -f "Check performed by:",$env:USERNAME
            $comments += "{0} {1}" -f "Check was done on :",(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
            $comments += "{0} {1}" -f "Check performed with powershell function",$functionName
            $comments += "{0}" -f ' '
            $comments += "{0}" -f "Remarks:"
            $comments += "{0}" -f ($check.comments -join "`n")
            
            # set finding status
            $findingStatus = switch($check.value){
                0       {'not_a_finding'}
                1       {'open'}
                2       {'not_applicable'}
                default {'not_reviewed'}
            }
        }
    }
    end{
        if(-not($skip)){
            # update the comments in the checklist file
            $PSSTIG.UpdateComment(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Comment         = ($comments -join "`n")
            })
        
            # update the status in the checklist file
            $PSSTIG.UpdateStatus(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
                Status          = $findingStatus
            })
        }

        # display the status from the checklist file
        if($DisplayStatus){
            $PSSTIG.GetFindingInfo(@{
                CheckListName   = $CheckListName
                FindingID       = $FindingID
            })
        }
    }
}
# test
