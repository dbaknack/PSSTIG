
declare @usingSQLLogin as int

set @usingSQLLogin = (
SELECT count(*)
FROM sys.sql_logins 
WHERE type_desc = 'SQL_LOGIN' AND is_disabled = 0)

if(@usingSQLLogin) = 0
begin
    select
        [result] = 0,
        [value]  = 'No SQL Login being used.'
end

if(@usingSQLLogin) > 0 
begin
    SELECT
    [name],
    [is_disabled]
    FROM sys.sql_logins 
    WHERE type_desc = 'SQL_LOGIN' AND is_disabled = 0
end
