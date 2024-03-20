declare @hasAudit int
set @hasAudit = 1

if(
    select count(*)
        from(
        SELECT name AS 'Audit Name',
        status_desc AS 'Audit Status',
        audit_file_path AS 'Current Audit File'
        FROM sys.dm_server_audit_status
    ) checKAudit
) = 0
begin
    set @hasAudit = 0
end

if(@hasAudit) = 0
begin
    select
        [Results] = 1,
        [Value]   = 'there is no audit'
end
if(@hasAudit) = 1
begin
    select
        Results = 1,
        [Value]   = 'there is an audit'
end

-- if(@hasAudit) = 1
-- begin
--     SELECT a.name AS 'AuditName',
--     s.name AS 'SpecName',
--     d.audit_action_name AS 'ActionName',
--     d.audited_result AS 'Result'
--     FROM sys.server_audit_specifications s
--     JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
--     JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
--     WHERE a.is_state_enabled = 1
--     AND d.audit_action_name IN (
--     'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
--     'AUDIT_CHANGE_GROUP',
--     'BACKUP_RESTORE_GROUP',
--     'DATABASE_CHANGE_GROUP',
--     'DATABASE_OBJECT_ACCESS_GROUP',
--     'DATABASE_OBJECT_CHANGE_GROUP',
--     'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
--     'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
--     'DATABASE_OWNERSHIP_CHANGE_GROUP',
--     'DATABASE_OPERATION_GROUP',
--     'DATABASE_PERMISSION_CHANGE_GROUP',
--     'DATABASE_PRINCIPAL_CHANGE_GROUP',
--     'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
--     'DATABASE_ROLE_MEMBER_CHANGE_GROUP', 
--     'DBCC_GROUP',
--     'LOGIN_CHANGE_PASSWORD_GROUP',
--     'SCHEMA_OBJECT_CHANGE_GROUP',
--     'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
--     'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
--     'SERVER_OBJECT_CHANGE_GROUP',
--     'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
--     'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
--     'SERVER_OPERATION_GROUP',
--     'SERVER_PERMISSION_CHANGE_GROUP',
--     'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
--     'SERVER_ROLE_MEMBER_CHANGE_GROUP',
--     'SERVER_STATE_CHANGE_GROUP',
--     'TRACE_CHANGE_GROUP'
--     )
--     Order by d.audit_action_name
-- end
