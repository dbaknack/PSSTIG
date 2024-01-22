SELECT m.name AS Member, 
	m.type_desc AS Type, 
	r.name AS Role 
	FROM sys.server_principals m 
	INNER JOIN sys.server_role_members rm ON m.principal_id = rm.member_principal_id 
	INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id 
	WHERE r.name IN ('sysadmin','securityadmin','serveradmin') 