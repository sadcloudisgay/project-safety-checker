This program scans a specified directory for files that might contain suspicious patterns related to potential security risks. 
It specifically looks at project and build files (like .csproj, .vcxproj, .sln, .props, and .targets). 
The program helps you identify files that could potentially be harmful by checking for patterns that could indicate malicious behavior or dangerous code.

# Detection Vectors
Here is a list of all the detection vectors used by the program:

High-Risk Patterns

<Exec Command=.*cmd.exe
<Exec Command=.*powershell
<Exec Command=.*curl
<Exec Command=.*wget
<Exec Command=.*Invoke-WebRequest
<Exec Command=.*Invoke-Expression
<Exec Command=.*start-process
<Exec Command=.*certutil
<Exec Command=.*bash
<Exec Command=.*sh
<Exec Command=.*python
<Exec Command=.*xcopy
<Exec Command=.*robocopy
<Exec Command=.*copy
<Exec Command=.*move
<Exec Command=.*del
<Exec Command=.*rm
<Exec Command=.*nslookup
<Exec Command=.*ping
<Exec Command=.*tracert
<Exec Command=.*ftp
<Exec Command=.*tftp
<Exec Command=.*netcat
<Exec Command=.*nc
<Exec Command=.*telnet
<Exec Command=.*attrib
<Exec Command=.*icacls
<Exec Command=.*schtasks
<Exec Command=.*taskkill
<Exec Command=.*tasklist
<Exec Command=.*net\s+user
<Exec Command=.*net\s+localgroup
Build and Target Manipulations

<Target Name=".*" AfterTargets="Build"
<Target Name=".*" BeforeTargets="Build"
<UsingTask TaskName=".*" TaskFactory="CodeTaskFactory"
<UsingTask TaskName=".*" AssemblyFile=".*"
Indicators of Potentially Obfuscated Code

\[System\.Text\.Encoding\]::Unicode\.GetString
\[System\.Convert\]::FromBase64String
System\.Reflection\.Assembly::Load
System\.IO\.File::ReadAllBytes
Lower-Risk Patterns
File and Script Imports

<Import Project=".*"
<Import Project=.*\.props
<Import Project=.*\.targets
Potentially Less Dangerous Build and Target Manipulations

<PropertyGroup>
<ItemGroup>
<Reference Include=".*"
