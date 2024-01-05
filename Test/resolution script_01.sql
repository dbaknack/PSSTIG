-- configuration params
declare @path_to_stig_audit_server nvarchar(max)
declare @audit_server_name nvarchar(max)
declare @specification_name nvarchar(max)


set @path_to_stig_audit_server  = 'A:\Audits\'
set @audit_server_name			= 'STIG_AUDIT_SERVER'
set @specification_name			= 'STIG_AUDIT_SERVER_SPECIFICATION'

-- start
declare @cmd_create_audit_server	nvarchar(max)
declare @cmd_turn_on_audit_server	nvarchar(max)
declare @audit_server_created		int = 0

set @cmd_create_audit_server =  '
CREATE SERVER AUDIT STIG_AUDIT_SERVER
 TO FILE ( FILEPATH ='+@path_to_stig_audit_server+' );'


if(
	select count(name)
	from sys.dm_server_audit_status
	where [name] = @audit_server_name) = 0
begin
	exec (@cmd_create_audit_server)
	print '> the audit server '+@audit_server_name+' already was created...'
	set @audit_server_created = (select 1)
end
else
begin
	set @audit_server_created = (select 0)
	print '> the audit server '+@audit_server_name+' already exists...'
end

declare @action_name table (
	id int,
	action_name varchar(max)
)
insert into @action_name
	select 1, 'successful_login_group'
	union
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

if(@audit_server_created) = 1
begin
	set @cmd_turn_on_audit_server = '
	ALTER SERVER AUDIT '+@audit_server_name+'
	WITH (STATE = ON);
	'
	print '> the audit server '+@audit_server_name+' turned on...'
end

if(
	select
	count(a.name)
	 from
	  sys.server_audit_specifications s join
	  sys.server_audits a
	on s.audit_guid = a.audit_guid join
	  sys.server_audit_specification_details d
	on s.server_specification_id = d.server_specification_id 
	where a.name = @audit_server_name and @specification_name = @specification_name) = (select count(*) from @action_name)
begin
	print 'there are some missing actions to create'
	
end





select * from @specification_groups



-- table for condition results
declare @check_condition table (
 check_type varchar(100),
 check_key  varchar(100),
 check_val  varchar(100)
)


select * from @specification_groups
where group_name not in(
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
  a.is_state_enabled  = 1)



-- create a specification
CREATE SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
FOR SERVER AUDIT STIG_AUDIT_SERVER


-- Drop the server audit
DROP SERVER AUDIT STIG_AUDIT_SERVER;



-- turn off the specification prior to addinf
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
WITH (STATE = OFF);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SUCCESSFUL_LOGIN_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (LOGOUT_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (LOGOUT_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (APPLICATION_ROLE_CHANGE_PASSWORD_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (AUDIT_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (BACKUP_RESTORE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_OBJECT_PERMISSION_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_OPERATION_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_OWNERSHIP_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_PERMISSION_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_PRINCIPAL_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_OBJECT_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_PRINCIPAL_IMPERSONATION_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (DBCC_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (LOGIN_CHANGE_PASSWORD_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (LOGOUT_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SCHEMA_OBJECT_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_OBJECT_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_OBJECT_PERMISSION_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_OPERATION_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_PERMISSION_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_PRINCIPAL_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_PRINCIPAL_IMPERSONATION_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (SERVER_STATE_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (TRACE_CHANGE_GROUP);

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
ADD (USER_CHANGE_PASSWORD_GROUP);

-- trun on
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION
WITH (STATE = ON);
