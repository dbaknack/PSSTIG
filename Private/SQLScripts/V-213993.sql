SELECT
    SERVERPROPERTY('ProductVersion') AS 'SQL Server Version',
    SERVERPROPERTY('ProductLevel') AS 'Service Pack Level',
    SERVERPROPERTY('Edition') AS 'Edition',
    SERVERPROPERTY('EngineEdition') AS 'Engine Edition',
    SERVERPROPERTY('IsClustered') AS 'Is Clustered',
    SERVERPROPERTY('IsFullTextInstalled') AS 'Full-Text Installed',
    SERVERPROPERTY('IsIntegratedSecurityOnly') AS 'Integrated Security Only',
    SERVERPROPERTY('IsHadrEnabled') AS 'Always On Availability Groups Enabled',
    SERVERPROPERTY('IsPolyBaseInstalled') AS 'PolyBase Installed',
    SERVERPROPERTY('IsReplicationInstalled') AS 'Replication Installed';
