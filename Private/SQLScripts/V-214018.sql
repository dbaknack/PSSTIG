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
        [specname] = s.[name],
        [actionname] = d.audit_action_name,
        [result] = d.audited_result
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