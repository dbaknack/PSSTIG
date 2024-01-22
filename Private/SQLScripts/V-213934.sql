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