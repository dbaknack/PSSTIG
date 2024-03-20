if(
	SELECT count(*)
	FROM sys.server_principals
	WHERE type in ('U','G')
	AND name LIKE '%$'
) > 0
begin
	select
	result = 1,
	name as 'Value'
	FROM sys.server_principals
	WHERE type in ('U','G')
	AND name LIKE '%$'
end
/*
|	Result	| value				|
|	1		| domain\loginname$ |
*/
if(
	SELECT count(*)
	FROM sys.server_principals
	WHERE type in ('U','G')
	AND name LIKE '%$'
) = 0
begin
select
	[result] = 0,
	[value] = 0
end
--|	Result	| value				|
--|	0		| domain\loginname$ |
