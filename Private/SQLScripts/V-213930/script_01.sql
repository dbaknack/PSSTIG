-- always return values as
-- result   -> 1 or 0. 1 is open, 0 is not open
-- value    -> the value of what is considered open or not open
declare @usingWindowsAuth  as int

set @usingWindowsAuth = (
    SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')    
    WHEN 1 THEN 0  -- windows auth
    WHEN 0 THEN 1  -- mixed
    END as [Authentication Mode]  
)

if(@usingWindowsAuth) = 0
begin
    select
        [result]    = 0,
        [value]     = 'Using Windows Authentication'
end

if(@usingWindowsAuth) = 1
begin
    select
        [result]    = 1,
        [value]     = 'Using Mixed Mode'
end



-- SELECT name 
-- FROM sys.sql_logins 
-- WHERE type_desc = 'SQL_LOGIN' AND is_disabled = 0;  
