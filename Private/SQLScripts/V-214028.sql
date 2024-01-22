DECLARE @temp_results TABLE (
    name        varchar(max),
    is_disabled varchar(max)
)
INSERT INTO @temp_results
SELECT
    name,
    is_disabled
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