# pass in a finding ID
# here is where the scripts to run are defined given the finding id
# this function gets updated with finding scripts to run, if any
Function Get-FindingChecks {
    param(
        [string]$finding_id
    )

    #$finding_id = 'V-214027'

    $checks_table = @{
        'V-214027' = @{
            check_1 = @{
                check_string_substitution_required = $true
                check_type = 'sql_instance_check'
                check_script = "
                SELECT case when count(*) > 0 then 1 else 0 end as  check_result,name check_value, 'there_is_a_telemetry_service_account' result_type
                FROM sys.server_principals
                WHERE name LIKE '%SQLTELEMETRY%'
                group by name
                "
                check_script_description = 'Checking to see if there is a telemetry service account in instance {0}...'
            }
        }
        'V-214026' = @{
            check_1 = @{
                check_string_substitution_required = $false
                 check_script_description = 'check_registry.'
                check_type = 'ps_script'
                check_script = {
                                    "$my_instances = (get-SQLInstances)
                    $reg_search_val = @()
                    foreach($inst in $my_instances.keys){
                        $reg_search_val += 'MSSQL13.MSSQLSERVER'
                        $reg_search_val += `"MSSQL13.$inst`"
                    }
                    foreach($reachable in $reg_search_val){
                        try{
                            $reg_vals = Get-ItemProperty -Path `"HKLM:\Software\Microsoft\Microsoft SQL Server\$reachable\CPE\`" -ErrorAction SilentlyContinue
   
                        }catch{

                        }
                        if($null -ne $reg_vals){
                            $reg_vals.CustomerFeedback;break
                        }
                    }

                    "
                }
            }

        } # here
        'V-214021' = @{
            check_1 = @{
                check_string_substitution_required = $false
                check_script_description = 'SQL Server must generate audit records for all direct access to the database(s).'
                check_type = 'sql_instance_check'
                check_script = "
                SELECT count(name) as check_result,name AS AuditName, predicate AS AuditFilter  
FROM sys.server_audits  
WHERE predicate IS NOT NULL
group by name, predicate
                "
            }
        }
        'V-214020' = @{
            check_1 = @{
                check_string_substitution_required = $false
                check_script_description = 'SQL Server must generate audit records when successful and unsuccessful accesses to objects occur.'
                check_type = 'sql_instance_check'
                check_script =
                "
                if(SELECT count(*)  from sys.dm_server_audit_status) = 0
                begin
                    select 0 check_result, NULL check_value, 'audit_configured_01' result_type
                end
                else
                begin
                SELECT name AS 'Audit Name',
                    status_desc AS 'Audit Status',
                    audit_file_path AS 'Current Audit File'
                FROM sys.dm_server_audit_status
                end
                "
            }
        }
        'V-214045' =  @{
            check_1 = @{
                check_string_substitution_required = $false
                check_script_description = 'authentication_method_check.'
                check_type = 'sql_instance_check'
                check_script =
                "
                                DECLARE @temp_results TABLE (
                        name varchar(max),
                        config_value varchar(max)
                    )
                    INSERT INTO @temp_results
                    EXEC master.sys.xp_loginconfig 'login mode';

                    select
                        case
                            when name = 'Windows NT Authentication'
                            then 0
                            else 1
                        end as 'check_result',
                        [check_value] = config_value,
                        result_type = 'authentication_method_check'
                    from
                        @temp_results
                "
            }
        }
        'V-214028' =  @{
            check_1 = @{
                check_string_substitution_required = $false
                check_script_description = 'sa_desabled_or_not.'
                check_type = 'sql_instance_check'
                check_script =
                "
                DECLARE @temp_results TABLE (
                    name varchar(max),
                    is_disabled varchar(max)
                )
                INSERT INTO @temp_results
                SELECT name, is_disabled
                FROM sys.sql_logins
                WHERE principal_id = 1;
               
                select
                    case
                        when is_disabled  = 'True'
                        then 0 -- means its a finding
                        else 1
                    end as 'check_result',
                    [check_value] = is_disabled,
                    result_type = 'sa_account_disabled'
                from
                    @temp_results
                "
            }
        }
        'V-213934' = @{
            check_1 = @{
                check_string_substitution_required = $false
                check_script_description = 'check permission over allocation to NT AUTHORITY\SYSTEM'
                check_type = 'sql_instance_check'
                check_script =
                "
                set NOCOUNT  ON
                declare @result_hash table (
                    my_key varchar(30),
                    my_value int
                )
                -- use this to store the local sys permissions
                declare @permissions_used_by_local_sys_account table (
                    permissions_ varchar(50)
                )
                declare @permissions_allowed_by_local_sys_account table (
                    permissions_ varchar(50)
                )
                declare @condition_found smallint
                set @condition_found = 0
               
                -- conditions for consideration
                insert into @result_hash
                SELECT 'ISClustered', cast(SERVERPROPERTY('IsClustered') as int) AS [IsClustered]
                union
                SELECT 'IsHadrEnabled',cast(SERVERPROPERTY('IsHadrEnabled') as int) AS [IsHadrEnabled]
               
               
                EXECUTE AS LOGIN = 'NT AUTHORITY\SYSTEM'
               
                -- list the permissions granted to local system account
                Insert into @permissions_used_by_local_sys_account
                SELECT [permission_name] FROM fn_my_permissions(NULL, 'server')
               
                if(@condition_found) = 0
                begin
                    -- when both 0, only 2 permissions are allowed for NT AUTHORITY\SYSTEM
                    if(select my_value from @result_hash where my_key = 'ISClustered') = 0
                    begin
                        if(select my_value from @result_hash where my_key = 'IsHadrEnabled') = 0
                        begin
                        print 'IsClustered is 0 and isHadrEnabled = 0 condition set'
                            set @condition_found = 1
                            insert into @permissions_allowed_by_local_sys_account
                            select permissions_granted
                            from
                            (
                                SELECT 'CONNECT SQL' as permissions_granted
                                union
                                SELECT 'VIEW ANY DATABASE' as permissions_granted
                            ) granted_permissions
                        end
                    end
                end
               
               
                if(@condition_found) = 0
                begin
                    -- when 1 and 0, only 3 permissions are allowed for NT AUTHORITY\SYSTEM
                    if(select my_value from @result_hash where my_key = 'ISClustered') = 1
                    begin
                        if(select my_value from @result_hash where my_key = 'IsHadrEnabled') = 0
                        print 'IsClustered is 1 and isHadrEnabled = 0 condition set'
                        begin
                        set @condition_found = 1
                            insert into @permissions_allowed_by_local_sys_account
                            select permissions_granted
                            from
                            (
                                SELECT 'CONNECT SQL' as permissions_granted
                                union
                                SELECT'VIEW SERVER STATE' as permissions_granted
                                union
                                SELECT 'VIEW ANY DATABASE' as permissions_granted
                            ) granted_permissions
                        end
                    end
                end
               
                if(@condition_found) = 0
                    begin
                    -- when 1 , only 5 permissions are allowed for NT AUTHORITY\SYSTEM
                    if (select my_value from @result_hash where my_key = 'IsHadrEnabled') = 1
                    begin
                    print 'IsHadrEnabled condition set'
                    set @condition_found = 1
                    insert into @permissions_allowed_by_local_sys_account
                    select permissions_granted
                    from
                        (
                            SELECT 'CONNECT SQL' as permissions_granted
                            union
                            SELECT'CREATE AVAILABILITY GROUP' as permissions_granted
                            union
                            SELECT 'ALTER ANY AVAILABILITY GROUP' as permissions_granted
                            union
                            SELECT 'VIEW SERVER STATE' as permissions_granted
                            union
                            SELECT 'VIEW ANY DATABASE' as permissions_granted
                        ) granted_permissions
                    end
                end
               
                REVERT
                declare @permissions_over_allocated int
                set @permissions_over_allocated = (
                    select
                    count(permissions_) permissions_over_allocated from (
                        select * from @permissions_used_by_local_sys_account where not exists(
                        select * from @permissions_allowed_by_local_sys_account
                        )
                    ) permissions_overallocated
                )
               
                select
                    case when (select @permissions_over_allocated) = 0
                        then 0 -- then not a finding
                        else 1 -- then is a finding
                    end check_result,
                    case when @permissions_over_allocated = 0
                        then  'no permissions over allocted for local system'
                        else 'permissions over allocated local system'
                    end check_value,
                    'permission_over_allocation_to_local_system' result_type
                "
            }
        }
        'V-214018' = @{
            check_1 = @{
                check_string_substitution_required  = $false
                check_script_description            = 'checks to see if there is an audit, and if the audit has a specification'
                check_type                          = 'sql_instance_check'
                check_script                        ="
                -- user params
                -- define as needed
                declare @param_specification_name varchar(100) =  'successful_login_group'
                
                
                -- table for final results
                declare @final_assesment table (
                    check_result nvarchar(100),
                    check_value  nvarchar(100),
                    result_type  nvarchar(100)
                )
                
                -- table for condition results
                declare @check_condition table (
                    check_type varchar(100),
                    check_key  varchar(100),
                    check_val  varchar(100)
                )
                
                declare
                    -- variables for result assignments (use as needed)
                    @_val  nvarchar(100),
                    @_key  nvarchar(100),
                    @_type nvarchar(100),
                
                    @finding_condition_met int,
                    @check_result int,
                    @check_value varchar(100),
                    @result_type varchar(100)
                
                
                -- condition: how many audits are there?
                insert into @check_condition
                select
                    [check_type] = 'audit_count',
                    [check_key]  = 'total_audits',
                    [check_val] = count(*)
                from (
                    select
                        name,
                        status_desc,
                        audit_file_path
                    from sys.dm_server_audit_status
                ) audit_status
                
                
                -- result assignment: the total number of audits
                set @_val = (
                    select check_val from @check_condition where
                        check_type = 'audit_count' and
                        check_key  = 'total_audits'
                )
                
                
                -- result assesment
                if(select @_val) = '0'
                begin
                    -- result assignment
                    set @finding_condition_met = (select 1)
                
                    insert into @final_assesment
                    select '1','there is no audit on this instance','audit_enabled_check'
                end
                else
                begin
                    set @finding_condition_met = (select 0)
                end
                
                if(@finding_condition_met) = 1
                begin
                    select * from @final_assesment; return
                end
                
                declare @specification table (
                    id int,
                    name varchar(100)
                )
                
                -- extensible to include more than one type of audit
                insert into @specification
                select 1,'successful_login_group' 
                
                insert into @check_condition
                select
                    [check_type] = 'specification_count',
                    [check_key]  = 'total_specifications',
                    [check_val] = count(*)
                from (
                    select
                        [auditname]  = a.[name],
                        [specname]	 = s.[name], 
                        [actionname] = d.audit_action_name, 
                        [result]	 = d.audited_result
                    from
                        sys.server_audit_specifications s join
                        sys.server_audits a
                            on s.audit_guid = a.audit_guid join
                        sys.server_audit_specification_details d
                            on s.server_specification_id = d.server_specification_id 
                    where
                        a.is_state_enabled  = 1 and
                        d.audit_action_name = (select name from @specification where name = @param_specification_name)
                ) specifications
                
                
                -- result assignment: the total number of specifications
                set @_val = (
                    select check_val from @check_condition where
                        check_type = 'specification_count' and
                        check_key  = 'total_specifications'
                )
                
                if(select @_val) = 0
                begin
                    -- result assignment
                    set @finding_condition_met = (select 1)
                
                    insert into @final_assesment
                    select '1','there is an audit on instance, but ther is no specification set','audit_specification_exist'
                end
                else
                begin
                    set @finding_condition_met = (select 0)
                    insert into @final_assesment
                    select '0','there is an audit on instance, and a specification','audit_specification_exist'
                end
                
                select * from @final_assesment
                "
            }
        }
        'V-214017' = @{
            check_1 = @{
                check_string_substitution_required  = $false
                check_script_description            = 'checks to see if there is an audit, and if the audit has the set specification'
                check_type                          = 'sql_instance_check'
                check_script                        =@'
                -- table for final results
                declare @final_assesment table (
                    check_result nvarchar(100),
                    check_value  nvarchar(100),
                    result_type  nvarchar(100)
                )
                
                -- table for condition results
                declare @check_condition table (
                    check_type varchar(100),
                    check_key  varchar(100),
                    check_val  varchar(100)
                )
                
                declare
                    -- variables for result assignments (use as needed)
                    @_val  nvarchar(100),
                    @_key  nvarchar(100),
                    @_type nvarchar(100),
                
                    @finding_condition_met int,
                    @check_result		 int,
                    @check_value		 varchar(100),
                    @result_type		 varchar(100)
                
                
                -- condition: how many audits are there?
                insert into @check_condition
                select
                    [check_type] = 'audit_count',
                    [check_key]  = 'total_audits',
                    [check_val] = count(*)
                from (
                    select
                        name,
                        status_desc,
                        audit_file_path
                    from sys.dm_server_audit_status
                ) audit_status
                
                
                -- result assignment: the total number of audits
                set @_val = (
                    select check_val from @check_condition where
                        check_type = 'audit_count' and
                        check_key  = 'total_audits'
                )
                
                -- result assesment
                if(select @_val) = '0'
                begin
                    -- result assignment
                    set @finding_condition_met = (select 1)
                
                    insert into @final_assesment
                    select '1','there is no audit on this instance','audit_enabled_check'
                end
                else
                begin
                    set @finding_condition_met = (select 0)
                end
                
                if(@finding_condition_met) = 1
                begin
                    select * from @final_assesment; return
                end
                
                declare @specification table (
                    id int,
                    name varchar(100)
                )
                
                -- extensible to include more than one type of audit
                insert into @specification
                select 2,'application_role_change_password_group'
                union
                select 3,'audit_change_group'
                union
                select 4,'backup_restore_group'
                union
                select 5,'database_change_group'
                union
                select 6,'database_object_change_group'
                union
                select 7,'database_object_ownership_change_group'
                union
                select 8,'database_object_permission_change_group'
                union
                select 9,'database_operation_group'
                union
                select 10,'database_ownership_change_group'
                union
                select 11,'database_permission_change_group'
                union
                select 12,'database_principal_change_group'
                union
                select 13,'database_principal_impersonation_group'
                union
                select 14,'database_role_member_change_group'
                union
                select 15,'dbcc_group'
                union
                select 16,'login_change_password_group'
                union
                select 17,'logout_group'
                union
                select 18,'schema_object_change_group'
                union
                select 19,'schema_object_ownership_change_group'
                union
                select 20,'schema_object_permission_change_group'
                union
                select 21,'server_object_change_group'
                union
                select 22,'server_object_ownership_change_group'
                union
                select 23,'server_object_permission_change_group'
                union
                select 24,'server_operation_group'
                union
                select 25,'server_permission_change_group'
                union
                select 26,'server_principal_change_group'
                union
                select 27,'server_principal_impersonation_group'
                union
                select 28,'server_role_member_change_group'
                union
                select 29,'server_state_change_group'
                union
                select 30,'trace_change_group'
                union
                select 31,'user_change_password_group'
                
                insert into @check_condition
                select
                    [check_type] = 'specification_count',
                    [check_key]  = 'total_specifications',
                    [check_val] = count(*)
                from (
                    select
                        [auditname]  = a.[name],
                        [specname]	 = s.[name], 
                        [actionname] = d.audit_action_name, 
                        [result]	 = d.audited_result
                    from
                        sys.server_audit_specifications s join
                        sys.server_audits a
                            on s.audit_guid = a.audit_guid join
                        sys.server_audit_specification_details d
                            on s.server_specification_id = d.server_specification_id 
                    where
                        a.is_state_enabled  = 1 and
                        d.audit_action_name in (select name from @specification)
                ) specifications
                
                -- result assignment: the total number of specifications
                set @_val = (
                    select check_val from @check_condition where
                        check_type = 'specification_count' and
                        check_key  = 'total_specifications'
                )
                
                
                if(select @_val) = 0
                begin
                    -- result assignment
                    set @finding_condition_met = (select 1)
                
                    insert into @final_assesment
                    select '1','there is an audit on instance, but ther is no specification set','audit_specification_exist'
                end
                else
                begin
                    set @finding_condition_met = (select 0)
                    insert into @final_assesment
                    select '0','there is an audit on instance, and a specification','audit_specification_exist'
                end
                
                select * from @final_assesment
'@
            }
        }
        'V-214016' = @{
            check_1 = @{
                check_string_substitution_required  = $false
                check_script_description            = 'checks to see if there is an audit, and if the audit has the set specification'
                check_type                          = 'sql_instance_check'
                check_script                        =@'
                -- table for final results
                declare @final_assesment table (
                    check_result nvarchar(100),
                    check_value  nvarchar(100),
                    result_type  nvarchar(100)
                )
                
                -- table for condition results
                declare @check_condition table (
                    check_type varchar(100),
                    check_key  varchar(100),
                    check_val  varchar(100)
                )
                
                declare
                    -- variables for result assignments (use as needed)
                    @_val  nvarchar(100),
                    @_key  nvarchar(100),
                    @_type nvarchar(100),
                
                    @finding_condition_met int,
                    @check_result		 int,
                    @check_value		 varchar(100),
                    @result_type		 varchar(100)
                
                
                -- condition: how many audits are there?
                insert into @check_condition
                select
                    [check_type] = 'audit_count',
                    [check_key]  = 'total_audits',
                    [check_val] = count(*)
                from (
                    select
                        name,
                        status_desc,
                        audit_file_path
                    from sys.dm_server_audit_status
                ) audit_status
                
                
                -- result assignment: the total number of audits
                set @_val = (
                    select check_val from @check_condition where
                        check_type = 'audit_count' and
                        check_key  = 'total_audits'
                )
                
                -- result assesment
                if(select @_val) = '0'
                begin
                    -- result assignment
                    set @finding_condition_met = (select 1)
                
                    insert into @final_assesment
                    select '1','there is no audit on this instance','audit_enabled_check'
                end
                else
                begin
                    set @finding_condition_met = (select 0)
                end
                
                if(@finding_condition_met) = 1
                begin
                    select * from @final_assesment; return
                end
                
                declare @specification table (
                    id int,
                    name varchar(100)
                )
                
                -- extensible to include more than one type of audit
                insert into @specification
                select 2,'application_role_change_password_group'
                union
                select 3,'audit_change_group'
                union
                select 4,'backup_restore_group'
                union
                select 5,'database_change_group'
                union
                select 6,'database_object_change_group'
                union
                select 7,'database_object_ownership_change_group'
                union
                select 8,'database_object_permission_change_group'
                union
                select 9,'database_operation_group'
                union
                select 10,'database_ownership_change_group'
                union
                select 11,'database_permission_change_group'
                union
                select 12,'database_principal_change_group'
                union
                select 13,'database_principal_impersonation_group'
                union
                select 14,'database_role_member_change_group'
                union
                select 15,'dbcc_group'
                union
                select 16,'login_change_password_group'
                union
                select 17,'logout_group'
                union
                select 18,'schema_object_change_group'
                union
                select 19,'schema_object_ownership_change_group'
                union
                select 20,'schema_object_permission_change_group'
                union
                select 21,'server_object_change_group'
                union
                select 22,'server_object_ownership_change_group'
                union
                select 23,'server_object_permission_change_group'
                union
                select 24,'server_operation_group'
                union
                select 25,'server_permission_change_group'
                union
                select 26,'server_principal_change_group'
                union
                select 27,'server_principal_impersonation_group'
                union
                select 28,'server_role_member_change_group'
                union
                select 29,'server_state_change_group'
                union
                select 30,'trace_change_group'
                union
                select 31,'user_change_password_group'
                
                insert into @check_condition
                select
                    [check_type] = 'specification_count',
                    [check_key]  = 'total_specifications',
                    [check_val] = count(*)
                from (
                    select
                        [auditname]  = a.[name],
                        [specname]	 = s.[name], 
                        [actionname] = d.audit_action_name, 
                        [result]	 = d.audited_result
                    from
                        sys.server_audit_specifications s join
                        sys.server_audits a
                            on s.audit_guid = a.audit_guid join
                        sys.server_audit_specification_details d
                            on s.server_specification_id = d.server_specification_id 
                    where
                        a.is_state_enabled  = 1 and
                        d.audit_action_name in (select name from @specification)
                ) specifications
                
                -- result assignment: the total number of specifications
                set @_val = (
                    select check_val from @check_condition where
                        check_type = 'specification_count' and
                        check_key  = 'total_specifications'
                )
                
                
                if(select @_val) = 0
                begin
                    -- result assignment
                    set @finding_condition_met = (select 1)
                
                    insert into @final_assesment
                    select '1','there is an audit on instance, but ther is no specification set','audit_specification_exist'
                end
                else
                begin
                    set @finding_condition_met = (select 0)
                    insert into @final_assesment
                    select '0','there is an audit on instance, and a specification','audit_specification_exist'
                end
                
                select * from @final_assesment
'@
            }
        }
    }
   
    [array]$checks_ids_list = $checks_table.keys

    $finding_runs_something = [bool]
    if($checks_ids_list -contains $finding_id){
        $finding_runs_something = $true
    }else{
        $finding_runs_something = $false
    }

    if(-not($finding_runs_something)){
        return 0
    }

    [array]$checks_list = $checks_table[$finding_id].keys

    $check_params = @()
    foreach($check_to_do in $checks_list){
        $check_params += $checks_table[$finding_id][$check_to_do]
    }
    return $check_params
}

# pass in results to evaluate, and a finding ID
# this function get updated with finding considerations, if any
Function Get-FindingExceptions2{
    param(
        [hashtable]$CheckResults,
        [string]$finding_id
    )
    # defined consideration by finding
    $finding_considerations_table = @{
        # each finding can have considertation or no considertaion
        'V-214027' = @{
            has_consideration   = $true
            considerations      = @{
                there_is_a_telemetry_service_account = @()
            }
        }
        'V-214028' = @{
            has_consideration   = $false
            considerations      = @{}
        }
        'V-214026' = @{
            has_consideration   = $false
            considerations      = @{}
        }
    }
    # check that the finding_id provided is defined in our considerations table
    [array]$finding_id_list = $finding_considerations_table.keys

    if($finding_id_list -notcontains $finding_id){
        Write-Error -Message "the finding provided '$finding_id' is not defined in the considerations table" -Category InvalidData
        return
    }
#    $finding_id = 'V-214027'

    # check to see if a consideration is defined for the particular finding id provided
    $has_considerations = $finding_considerations_table.$finding_id.has_consideration
   
    if(-not($has_considerations)){
        return $CheckResults
    }
   
    # since no consideration will be needed for finding, with no considerations, only thing that will need consideration will be required
    # the keys get added here for each of the result set types returned for the given finding id's
    $my_consideration_params = @{
        there_is_a_telemetry_service_account = @{
            when_check_result_is                    = [int]
            remark_text_is                          = @()
            update_check_status_to_open             = [bool]
            update_check_status_to_not_a_finding    = [bool]
            update_check_status_to_not_applicable   = [bool]
            update_check_status_to_not_reviewed     = [bool]
        }
    }

    # here is where you define the staus given a result
    switch($finding_id){
        'V-214027' {
            $things_to_consider_list = @()
            $my_consideration_params.there_is_a_telemetry_service_account.when_check_result_is                  = 1
            $my_consideration_params.there_is_a_telemetry_service_account.remark_text_is                        += "there is a telemetry_service_account, but the host cannot reach out to the internet."
            $my_consideration_params.there_is_a_telemetry_service_account.remark_text_is                        += "no logs will be send out to microsoft."
            $my_consideration_params.there_is_a_telemetry_service_account.remark_text_is                        += "stig deems this not a finding, if auditing of telemetry data is not required"
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_open           = $false
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_not_a_finding  = $true
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_not_applicable = $false
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_not_reviewed   = $false
            $finding_considerations_table[$finding_id].considerations.there_is_a_telemetry_service_account += (ConvertFrom-Hashtable ($my_consideration_params.there_is_a_telemetry_service_account))
       
            $my_consideration_params.there_is_a_telemetry_service_account.when_check_result_is                  = 0
            $my_consideration_params.there_is_a_telemetry_service_account.remark_text_is                        += "There is no telemetry_service account on instance"
            $my_consideration_params.there_is_a_telemetry_service_account.remark_text_is                        += "No logs will be send out to microsoft from instance."
            $my_consideration_params.there_is_a_telemetry_service_account.remark_text_is                        += "stig deems this not a finding, if auditing of telemetry data is not required"
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_open           = $false
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_not_a_finding  = $true
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_not_applicable = $false
            $my_consideration_params.there_is_a_telemetry_service_account.update_check_status_to_not_reviewed   = $false
            $finding_considerations_table[$finding_id].considerations.there_is_a_telemetry_service_account += (ConvertFrom-Hashtable ($my_consideration_params.there_is_a_telemetry_service_account))

            # here we update the list of considerations to be made by category
            $things_to_consider_list += 'there_is_a_telemetry_service_account'
        }
        default {
            Write-Error -Message "the finding id provided '$finding_id' does has considerations as definable, but there is nothing set... there is missing data assignment" -Category NotImplemented
            return
        }
    }
   
    # here we want to consider things that are in the hashtable
    $new_result_set = @{}
    foreach($result_set in $CheckResults.keys){
        $my_result_set = $CheckResults.$result_set
        $new_result_set += @{$result_set = $null}
        $new_result_set.$result_set += @{'considerations'=@{}}
        $new_result_set.$result_set += @{'results'=@()}
       

        $my_final_considerations = $null
        # given the result_type for the check performed. the considerations are evaluated
        $considerations = $finding_considerations_table[$finding_id].considerations[($my_result_set.result_type)]

        $my_final_considerations = $considerations | select-object -Property * | where-object {($_.when_check_result_is) -eq ($my_result_set.check_result)}
       
        if($null -ne $my_final_considerations){
           $new_result_set.$result_set.considerations = $my_final_considerations
        }
        $new_result_set.$result_set.results += @{'original_results' = $my_result_set}
   
    }

    # only one thing should ever be true
    foreach($result_set in $new_result_set.keys){

        if($new_result_set.$result_set.considerations.update_check_status_to_open){
           $new_result_set.$result_set.results += @{status = 'open'}
        }
        if($new_result_set.$result_set.considerations.update_check_status_to_not_applicable){
            $new_result_set.$result_set.results += @{status = 'not_applicable'}
        }
        if($new_result_set.$result_set.considerations.update_check_status_to_not_reviewed){
            $new_result_set.$result_set.results += @{status = 'not_reviewed'}
        }
        if($new_result_set.$result_set.considerations.update_check_status_to_not_a_finding){
            $new_result_set.$result_set.results += @{status = 'not_a_finding'}
        }
    }
    return $new_result_set

}

# use to query database
Function Invoke-UDFSQLCommand{
    param(
        [hashtable]$Query_Params
    )

    $processname = 'Invoke-UDFSQLCommand'
    $sqlconnectionstring = "
        server                          = $($Query_Params.instance_name);
        database                        = $($Query_Params.database_name);
        trusted_connection              = true;
        application name                = $processname;"
    # sql connection, setup call
    $sqlconnection                  = new-object system.data.sqlclient.sqlconnection
    $sqlconnection.connectionstring = $sqlconnectionstring
    $sqlconnection.open()
    $sqlcommand                     = new-object system.data.sqlclient.sqlcommand
    $sqlcommand.connection          = $sqlconnection
    $sqlcommand.commandtext         = ($Query_Params.query)
    # sql connection, handle returned results
    $sqladapter                     = new-object system.data.sqlclient.sqldataadapter
    $sqladapter.selectcommand       = $sqlcommand
    $dataset                        = new-object system.data.dataset
    $sqladapter.fill($dataset) | out-null
    $resultsreturned               += $dataset.tables
    $sqlconnection.close() # the session opens, but it will not close as expected
    $sqlconnection.dispose() # TO-DO: make sure the connection does close
    $resultsreturned
}

# use this to convert hashtables to psobjects
Function ConvertFrom-Hashtable {
      [CmdletBinding()]
      Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)]
          [hashtable]$MyHashtable
      )
      PROCESS {
          $results = @()
 
          $MyHashtable | ForEach-Object{
              $result = New-Object psobject;
              foreach ($key in $_.keys) {
                  $result | Add-Member -MemberType NoteProperty -Name $key -Value $_[$key]
               }
               $results += $result;
           }
          return $results
      }
}
# use this to get sql instance names
Function Get-SqlInstances {

    Param($ServerName = [System.Net.Dns]::GetHostName())
   
 
    $LocalInstances = @()
 
    [array]$Captions = Get-WmiObject win32_service -ComputerName $ServerName |
      where {
        $_.Name -match "mssql*" -and
        $_.PathName -match "sqlservr.exe"
      } |
        foreach {$_.Caption}
 
    foreach ($Caption in $Captions) {
      if ($Caption -eq "MSSQLSERVER") {
        $LocalInstances += "MSSQLSERVER"
      } else {
        $Temp = $Caption |
          foreach {$_.split(" ")[-1]} |
            foreach {$_.trimStart("(")} |
              foreach {$_.trimEnd(")")}
 
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $check_description. Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              'Stopped' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              'Yes' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              '0' {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $check_description. Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              'using_tls' {
                  $CheckResultsTable.status = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'. $check_description. Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
     
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 0} {
                  $CheckResultsTable.status = 'not_a_finding'
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
                  $CheckResultsTable.status = 'Open'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
              {$_ -eq 'not_a_finding'} {
                  $CheckResultsTable.status = 'not_a_finding'
                  $comment_string = "`Host '{0}' check, finding '{1}' for finding ID '{2}'.$($CheckResultsTable.check_description). Review {3} for resolution"
                  $comment_string = $comment_string -f $CheckResultsTable.host_name,$CheckResultsTable.status,$CheckResultsTable.finding_id, $CheckResultsTable.ResolutionFile
                  $CheckResultsTable.comments = $comment_string
              }
          }
      $check_object = ConvertFrom-Hashtable  $CheckResultsTable | Select-Object -Property * -ExcludeProperty ('csv_formatted','check_results')
      $CheckResultsTable.csv_formatted = ($check_object | convertto-csv -NoTypeInformation)
      $CheckResultsTable
}
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
Function Run-Finding213932{
    param([string]$InstanceName,[string]$enclave)

  $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
  $finding_id                = 'V-213932'
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

# written from home

Function Run-Finding214018{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214018'
    $remediate_file_name       = 'Remediate-Concurrent_Logons_Logs.md'
    $check_description         = 'SQL Server must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
    $cat_level                 = '2'
    # test
    $instanceName = 'DEV-SQL01\SANDBOX01'
    $enclave = 'test'
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
Function Run-Finding214017{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214017'
    $remediate_file_name       = 'Remediate-Generate_Start_End_Logs.md'
    $check_description         = 'SQL Server must generate audit records showing starting and ending time for user access to the database(s).'
    $cat_level                 = '2'
   
        $instanceName = 'DEV-SQL01\SANDBOX01'
        $enclave = 'test'
    

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
Function Run-Finding214016{
    param([string]$InstanceName,[string]$enclave)

    $documentation_parent_path = '\\petencnfs04\CCRI_LIBRARY\SysAd NIPRNET CM STIGS\RemediationDocumentation\'
    $finding_id                = 'V-214016'
    $remediate_file_name       = 'Remediate-Generate_Start_End_Logs.md'
    $check_description         = 'SQL Server must generate audit records showing starting and ending time for user access to the database(s).'
    $cat_level                 = '2'
   
        $instanceName = 'DEV-SQL01\SANDBOX01'
        $enclave = 'test'
    

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
