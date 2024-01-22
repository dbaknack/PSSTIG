DECLARE @temp_results TABLE (
    name            varchar(max),
    config_value    varchar(max)
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