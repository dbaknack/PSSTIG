if(select count(*)  from sys.dm_server_audit_status) = 0
begin
    select 0 check_result, NULL check_value, 'audit_configured_01' result_type
end
else
begin
    select
        name            AS 'Audit Name',
        status_desc     AS 'Audit Status',
        audit_file_path AS 'Current Audit File'
    FROM sys.dm_server_audit_status
end 