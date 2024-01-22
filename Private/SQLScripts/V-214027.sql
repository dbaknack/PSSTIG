select
    case when count(*) > 0
        then 1
        else 0
    end as check_result,
    name check_value,
    'there_is_a_telemetry_service_account' result_type
from
    sys.server_principals
where
    name like '%SQLTELEMETRY%'
group by
    name