SELECT
    count(name) as check_result,
    name as AuditName,
    predicate as AuditFilter  
FROM sys.server_audits  
WHERE predicate IS NOT NULL
group by name, predicate