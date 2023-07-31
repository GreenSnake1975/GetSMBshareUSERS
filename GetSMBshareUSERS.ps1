<#
получить на вход адрес smb-папки 

прочитать smb-права на нее -- список объектов (группы+пользователи)

для каждлого объекта запускаем рекурсивный обход, на каждом шаге передаем в рекурсию : 
	-- адрес smb-папки 
	-- список объектов (имен групп безопасности), которые привели к текущему объекту (на первом шаге список пустой)
	-- уровень доступа
	-- текущий объект
Обход: 
	-- если объект не контейнер (УЗ ПК/пользователя) -- выводим результат (smb-папка + путь объектов + права + конечный объект (тип+логин+имя))
	-- если объект контейнер (группа безопасности) : 
		* добавляем группу в список который привел в текущее положение в дереве обхода, 
		* получаем список членов этой группы 
		* для каждого из членов группы запускаем обход 
#>

param(
    [Parameter(Mandatory=$true)][string]   $SMBShare
); 

Class SMBShareUser{
	[string] $SMBShare; 
	[string] $AccessType; 
	[string] $Path; 
	[string] $ADName;
	[string] $Name;
	[string] $ADType;

	SMBShareUser([string] $_SMBShare, [string] $_AccessType, [string] $_Path, [string] $_ADName, [string] $_Name, [string] $_ADType){
		$this.Path = $_Path; 
		$this.Name = $_Name; 
		$this.ADName = $_ADName; 
		$this.ADType = $_ADType; 
		$this.SMBShare = $_SMBShare; 
		$this.AccessType = $_AccessType; 
	}
}
function Recursive {
	[cmdletbinding()]
	param (
		[Parameter(Mandatory=$true)][string] $CurrSmbShare, 
		[Parameter(Mandatory=$true)][AllowEmptyCollection()][System.Collections.ArrayList] $CurrPath, 
		[Parameter(Mandatory=$true)][Microsoft.ActiveDirectory.Management.ADEntity] $CurrObj, 
		[Parameter(Mandatory=$true)][string] $CurrAccess
	)
	switch ($CurrObj.ObjectClass) {
		'group' {  
			$CurrPath.Add($CurrObj.Name ) | Out-Null; 
			Get-ADGroup $CurrObj.Name | Get-ADGroupMember | ForEach-Object {
				Recursive -CurrPath $CurrPath -CurrObj $_ -CurrAccess $CurrAccess -CurrSmbShare $CurrSmbShare
			} 
		}
		'user' { 
			[SMBShareUser]::new( $CurrSmbShare, $CurrAccess, $CurrPath.ToArray() -join "`n", $CurrObj.samaccountname, $CurrObj.name, $CurrObj.ObjectClass); 
		}
		'computer' {  
			[SMBShareUser]::new( $CurrSmbShare, $CurrAccess, $CurrPath.ToArray() -join "`n", $CurrObj.name, '', $CurrObj.ObjectClass); 

		}
		Default {}
	}
}

($curSMBServer,$curSMBShare) = $SMBShare.split('\')[2..3];
if(($null -ne $curSMBServer) -and ($null -ne $curSMBShare)) {
	Invoke-Command -ComputerName $curSMBServer -ScriptBlock { param($ShareName) ; get-smbshare -Name $ShareName | Get-SmbShareAccess } -ArgumentList $curSMBShare |
	Where-Object -Property AccountName -ILike 'TONARPLUS\*' |
		ForEach-Object {
			$currAccountName = ($_.AccountName.split('\'))[1] ; 
			[System.Collections.ArrayList]$CurrPath =  New-Object System.Collections.ArrayList($null); 
			Recursive -CurrPath $CurrPath `
				-CurrAccess $_.AccessRight.ToString() `
				-CurrObj (Get-ADObject -Filter {(name -like $currAccountName) -or (samaccountname -like $currAccountName)}) `
				-CurrSmbShare $SMBShare ; 
		}
}

# (Get-ADObject -Filter {(name -like $currAccountName) -or (samaccountname -like $currAccountName)}).gettype()