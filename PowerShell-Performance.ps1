## 1. Measuring command performance
# 1a. Easiest - measure-command
Measure-Command {
    0..1000 | ForEach-Object {$i++} 
}

# 1b. Differentiating DateTime - good inside script (or, if want to run and see the result), for specific function
[datetime]$StartMS = (Get-Date)
0..1000 | ForEach-Object {$i++} 
[datetime]$EndMS =  (Get-Date)
Write-Host "This script took $(($EndMS - $StartMS).TotalMilliseconds) milliseconds to run."

# 1c. Get accurate time calc using Stopwatch class: It starts, constantly keeps the time since it was started and can be stopped at any moment.
$stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
0..1000 | ForEach-Object {$i++} 
$stopWatch.Stop()
$stopWatch.Elapsed

## 2. Performance impact is EVERYWHERE (e.g. Arrays)
Measure-Command {
    $r = New-Object System.Collections.ArrayList;
    $r.add("hi");$r.add("bye");$r.add("fly")
} | Select-Object Seconds, Milliseconds

Measure-Command {
    $MyArr = @(); 
    $MyArr += "hi";$MyArr += "bye";$MyArr += "fly"
} | Select-Object Seconds, Milliseconds

# 3. Grouping with Hash Tables
function global:Group-ObjectFast
{
   param
   (
       [Parameter(Mandatory,Position=0)] 
       [Object]
       $Property,
 
       [Parameter(ParameterSetName='HashTable')]
       [Alias('AHT')]
       [switch]
       $AsHashTable,
 
       [Parameter(ValueFromPipeline)]
       [psobject[]]
       $InputObject,
 
       [switch]
       $NoElement,
 
       [Parameter(ParameterSetName='HashTable')]
       [switch]
       $AsString,
 
       [switch]
       $CaseSensitive
   )
  
   begin 
   {
       # if comparison needs to be case-sensitive, use a 
       # case-sensitive hash table, 
       if ($CaseSensitive)
       {
           $hash = [System.Collections.Hashtable]::new()
       }
       # else, use a default case-insensitive hash table
       else
       {
           $hash = @{}
       }
   }
 
   process
   {
       foreach ($element in $InputObject)
       {
           # take the key from the property that was requested
           # via -Property
 
           # if the user submitted a script block, evaluate it
           if ($Property -is [ScriptBlock ])
           {
               $key = & $Property
           }
           else
           {
               $key = $element.$Property
           }
           # convert the key into a string if requested
           if ($AsString)
           {
               $key = "$key"
           }
           
           # make sure NULL values turn into empty string keys
           # because NULL keys are illegal
           if ($key -eq $null) { $key = '' }
           
           # if there was already an element with this key previously,
           # add this element to the collection
           if ($hash.ContainsKey($key))
           {
               $null = $hash[$key]. Add($element)
           }
           # if this was the first occurrence, add a key to the hash table
           # and store the object inside an arraylist so that objects
           # with the same key can be added later
           else
           {
               $hash[$key] = [ System.Collections.ArrayList]@($element)
           }
       }
   }
 
   end
   {
       # default output are objects with properties
       # Count, Name, Group
       if ($AsHashTable -eq $false)
       {
           foreach ($key in $hash. Keys)
           {
               $content = [Ordered]@{
                   Count = $hash[$key].Count
                   Name = $key
               }
               # include the group only if it was requested
               if ($NoElement -eq $false)
               {
                   $content["Group"] = $hash[$key]
               }
               
               # return the custom object
               [PSCustomObject]$content
           }
       }
       else
       {
           # if a hash table was requested, return the hash table as-is
           $hash
       }
   }
}

Measure-Command {
    Get-ChildItem c:\windows\system32 -Recurse -ErrorAction SilentlyContinue | Group-Object extension | Sort-Object count | Select-Object -First 5
} | Select-Object seconds, milliseconds

Measure-Command {
    Get-ChildItem c:\windows\system32 -Recurse -ErrorAction SilentlyContinue | Group-ObjectFast extension | Sort-Object Count | Select-Object -Last 5
} | Select-Object seconds, milliseconds

# 4. WMI/CIM: Go(o)d is in the details..
Measure-Command {
    Get-CimInstance -ClassName Win32_Process | Where-Object name -eq "explorer.exe"
} | Select-Object Seconds, Milliseconds

Measure-Command {
    Get-CimInstance -Query "SELECT * FROM Win32_Process WHERE name LIKE 'explorer%'"
} | Select-Object Seconds, Milliseconds

Measure-Command {
    Get-CimInstance -ClassName Win32_Process -Filter "name LIKE 'explorer%'"
} | Select-Object Seconds, Milliseconds

# 5. Print a single line. That's it. How hard can it be? ;-)
$file = 'C:\temp\useragentStrings.csv'

Measure-Command { 
    (Get-Content $file)[9999]
} | Select-Object Seconds, Milliseconds

Measure-Command {
    Get-content $file | Select-Object -first 1 -skip 9999
} | Select-Object Seconds, Milliseconds

Measure-Command {
    Get-Content $file -TotalCount 10000 | Select-Object -Last 1
} | Select-Object Seconds, Milliseconds

Measure-Command {
    Get-Content $file | Select-Object -Index 9999
} | Select-Object Seconds, Milliseconds

# using .NET system.IO.StreamReader (P.S. which is GREAT to ReadNext)
function Get-Line([String] $path, [Int32] $index)
{
    [System.IO.StreamReader] $reader = New-Object `
        -TypeName 'System.IO.StreamReader' `
        -ArgumentList ($path, $true);
    [String] $line = $null;
    [Int32] $currentIndex = 0;

    try
    {
        while (($line = $reader.ReadLine()) -ne $null)
        {
            if ($currentIndex++ -eq $index)
            {
                return $line;
            }
        }
    }
    finally
    {
        $reader.Close();
    }
    return $null;
}

Measure-Command {
    Get-Line $file 9999
} | Select-Object Seconds, Milliseconds
    
# a ha! what about [System.IO.File]::ReadAllLines
Measure-command { 
    ([System.IO.File]::ReadAllLines($file))[9999] 
} | Select-Object Seconds, Milliseconds

## 6. Event Logs
Measure-Command {
    Get-WinEvent -LogName Security | Where-Object EventID -eq 4624
} | Select-Object Seconds, Milliseconds

$XMLFilter = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624)]]</Select>
  </Query>
</QueryList>
'@

Measure-Command {
    Get-WinEvent -FilterXml $XMLFilter
} | Select-Object Seconds, Milliseconds    

Measure-Command {
    Get-WinEvent -FilterHashtable @{logname='Security';id=4624}
} | Select-Object Seconds, Milliseconds    

# Everything counts in large amounts
$XMLFilter = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4688)]]</Select>
  </Query>
</QueryList>
'@

Measure-Command {
    Get-WinEvent -FilterXml $XMLFilter
} | Select-Object Seconds, Milliseconds    

Measure-Command {
    Get-WinEvent -FilterHashtable @{logname='Security';id=4688}
} | Select-Object Seconds, Milliseconds    

# ...Or WEC? Or just use a DB / SIEM ;)

## 7. Remoting 
# 7a. PSSessions Vs. "one-time Invoke-Command"
Invoke-Command -ComputerName DC1 -ScriptBlock {ipconfig}
# vs.
$pssession = New-PSSession -ComputerName DC1
Invoke-Command -Session $pssession -ScriptBlock {ipconfig}

# 7b. Setting WinRM memory consumption for PowerShell Remoting
Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB 4096 # 4GB
set-Item WSMan:\localhost\Plugin\Microsoft.PowerShell\Quotas\MaxMemoryPerShellMB 4096 # 4GB
# Restart the service to take effect
Restart-Service winrm

# 8. AD queries - When a protocol/API can be BOTH the slowest AND quickest??!? :-()
Measure-Command {
    ([adsisearcher]"serviceprincipalname=*SQL*").FindAll()
} | select seconds, milliseconds

Measure-Command {
    Get-ADUser -Filter * -Properties serviceprincipalname | where ServicePrincipalName -Like "*SQL*"
} | select seconds, milliseconds

Measure-Command {
    Get-ADUser -Filter {ServiceprincipalName -like "*SQL*"} -Properties serviceprincipalname
} | select seconds, milliseconds

# Now let's compare S.DS.Protocols vs. AD module/ADWS vs. S.DS.DirectoryServices vs. ADSISearcher

# Get the s.ds.p Module for LDAP connections query from https://www.powershellgallery.com/packages/S.DS.P
Install-Module -Name S.DS.P

# prepare connection/objects
[string]$DomainDN = ([adsi]'').distinguishedName
Import-Module c:\temp\S.DS.P.psm1
Add-Type -AssemblyName system.directoryservices.protocols
Get-LdapConnection
$ldap = Get-LdapConnection
$s = New-Object System.DirectoryServices.DirectorySearcher;
$user = 'yossis'

# Get a single user
Measure-Command { Find-LdapObject -LdapConnection $Ldap -SearchFilter:"(&(samaccountname=$user)(objectClass=user)(objectCategory=Person))" -searchScope Subtree -PageSize 10000 -searchBase $DomainDN} | select @{n='Method';e={'S.DS.P'}}, TotalMilliseconds
Measure-Command { Get-ADUser -Identity $user}  | select @{n='Method';e={'AD module/ADWS'}}, TotalMilliseconds
Measure-Command { $s.Filter = "(&(objectcategory=person)(objectclass=user)(Samaccountname=$user))";$s.FindOne()}  | select @{n='Method';e={'S.DS.DirectoryServices'}}, TotalMilliseconds
Measure-Command { ([adsisearcher]"(&(objectcategory=person)(objectclass=user)(Samaccountname=$user))").findone()}  | select @{n='Method';e={'ADSISearcher'}}, TotalMilliseconds

# Get all users
Measure-Command { Find-LdapObject -LdapConnection $Ldap -SearchFilter:"(&(objectClass=user)(objectCategory=organizationalPerson))" -searchScope Subtree -PageSize 10000 -searchBase $DomainDN} | select @{n='Method';e={'S.DS.P'}}, TotalMilliseconds
Measure-Command { Get-ADUser -Filter *}  | select @{n='Method';e={'AD module/ADWS'}}, TotalMilliseconds
Measure-Command { $s.Filter = "(&(objectcategory=person)(objectclass=user))";$s.FindAll()}  | select @{n='Method';e={'S.DS.DirectoryServices'}}, TotalMilliseconds
Measure-Command { ([adsisearcher]"(&(objectcategory=person)(objectclass=user))").FindAll()} | select @{n='Method';e={'ADSISearcher'}}, TotalMilliseconds
# Mmm... let's run this once again. AND again. AND AGAIN!

# 9. Copying without WinAPI suckZs..
# Robo-WHO?
measure-command {
    robocopy $Env:SystemRoot\System32\calc.exe $Env:USERPROFILE\Desktop\calc.exe
} | Select-Object Seconds, Milliseconds

# Using Copy-Item 
measure-command {
    Copy-Item $Env:SystemRoot\System32\calc.exe $Env:USERPROFILE\Desktop\calc.exe
} | Select-Object Seconds, Milliseconds

# Now, Let's use WIN API to Copy file
$MethodDefinition = @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
public static extern bool CopyFile(string lpExistingFileName, string lpNewFileName, bool bFailIfExists);
'@
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru

measure-command {
    $Kernel32::CopyFile("$($Env:SystemRoot)\System32\calc.exe", "$($Env:USERPROFILE)\Desktop\calc.exe", $False)
} | Select-Object Seconds, Milliseconds

# 10. Finding Nemo ;) <my fileZ>
Measure-Command { 
    Get-ChildItem -Path C:\Dropbox\ -Recurse | Where-Object name -like "*its only a shell.pptx*"
} | Select-Object Seconds, Milliseconds

Import-Module C:\Temp\Communary.FileExtensions\Communary.FileExtensions.psd1
Measure-Command { 
    Invoke-FastFind -File "its only a shell.pptx" -Path C:\Dropbox\ -Recurse
} | Select-Object Seconds, Milliseconds

# 11. NetworkInformation.Ping vs. Win32_PingStatus + WaitAll() Threading Task RulZ
$Addr = "www.cnn.com", "104.17.188.107", "www.google.com", "www.ynet.co.il"

Measure-Command {
    Test-Connection -ComputerName $Addr -Count 1
} | Select-Object Seconds, Milliseconds

Measure-Command {
    $Addr | ForEach-Object {Test-Connection $_ -Count 1}
} | Select-Object Seconds, Milliseconds

Measure-Command {
    $Ping = $Addr | ForEach-Object {(New-Object System.Net.NetworkInformation.Ping).SendPingAsync($_,20)}
    [Threading.Tasks.Task]::WaitAll($Ping);
} | Select-Object Seconds, Milliseconds
# Get IPs only where Success
$SuccessIPs = ($Ping.Result | Where-Object Status -eq Success | Select-Object -ExpandProperty address).IPAddressToString
$SuccessIPs

# 12. Replace ForEach-Object with a script block
Measure-Command {
    1..1000000 | 
        ForEach-Object {
            "Line $_"
        }
    } | Select-Object Seconds, Milliseconds
    
    Measure-Command {
    1..1000000 | 
        & { process {
            "Line $_"
        }} 
    } | Select-Object Seconds, Milliseconds
    
# 13. Multi-What?
1..10 | ForEach-Object { Start-Sleep -Seconds 1; $_ }

1..10 | ForEach-Object -ThrottleLimit 5 -Parallel { Start-Sleep -Seconds 1; $_ }

1..10 | ForEach-Object -ThrottleLimit 10 -Parallel { Start-Sleep -Seconds 1; $_ }

# So what about Windows PowerShell?
Install-Module -Name PSParallel -Scope CurrentUser -Force # Uses Invoke-Parallel Command

# Note that each thread runs in its own environment, yet can use $using:
$LocalVar = "Line no."
1..10 | ForEach-Object -ThrottleLimit 10 -Parallel { Start-Sleep -Seconds 1; "$LocalVar $_" }

1..10 | ForEach-Object -ThrottleLimit 10 -Parallel { Start-Sleep -Seconds 1; "$using:LocalVar $_" }

# 14. Don't forget to Clean Up (Your mom doesn't do your Objects!) 
[gc]::Collect()

# 15. Go to the Core of things!
# Windows PowerShell 5.1 Latest update vs. PWSH v7 preview 6
Measure-Command { Get-ChildItem $env:windir -Recurse -file | Sort-Object Length} | Select-Object Seconds, Milliseconds
