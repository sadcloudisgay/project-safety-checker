using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

class Program
{
    static readonly List<Regex> HighRiskPatterns = new List<Regex>
    {
        new Regex(@"<Exec Command=.*cmd\.exe", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*powershell", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*curl", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*wget", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*Invoke-WebRequest", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*Invoke-Expression", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*start-process", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*certutil", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*bash", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*sh", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*python", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*xcopy", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*robocopy", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*copy", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*move", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*del", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*rm", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*nslookup", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*ping", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*tracert", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*ftp", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*tftp", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*netcat", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*nc", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*telnet", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*attrib", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*icacls", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*schtasks", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*taskkill", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*tasklist", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*net\s+user", RegexOptions.IgnoreCase),
        new Regex(@"<Exec Command=.*net\s+localgroup", RegexOptions.IgnoreCase),

        new Regex(@"<Target Name="".*"" AfterTargets=""Build""", RegexOptions.IgnoreCase),
        new Regex(@"<Target Name="".*"" BeforeTargets=""Build""", RegexOptions.IgnoreCase),
        new Regex(@"<UsingTask TaskName="".*"" TaskFactory=""CodeTaskFactory""", RegexOptions.IgnoreCase),
        new Regex(@"<UsingTask TaskName="".*"" AssemblyFile="".*""", RegexOptions.IgnoreCase),
        new Regex(@"<Target Name="".*"" DependsOnTargets="".*""", RegexOptions.IgnoreCase),

        new Regex(@"\[System\.Text\.Encoding\]::Unicode\.GetString", RegexOptions.IgnoreCase),
        new Regex(@"\[System\.Convert\]::FromBase64String", RegexOptions.IgnoreCase),
        new Regex(@"System\.Reflection\.Assembly::Load", RegexOptions.IgnoreCase),
        new Regex(@"System\.IO\.File::ReadAllBytes", RegexOptions.IgnoreCase)
    };

    static readonly List<Regex> LowerRiskPatterns = new List<Regex>
    {
        new Regex(@"<Import Project="".*""", RegexOptions.IgnoreCase),
        new Regex(@"<Import Project=.*\.props", RegexOptions.IgnoreCase),
        new Regex(@"<Import Project=.*\.targets", RegexOptions.IgnoreCase),

        new Regex(@"<PropertyGroup>", RegexOptions.IgnoreCase),
        new Regex(@"<ItemGroup>", RegexOptions.IgnoreCase),
        new Regex(@"<Reference Include="".*""", RegexOptions.IgnoreCase)
    };

    static void Main(string[] args)
    {
        Console.WriteLine("Please enter the directory you want to scan:");
        string directoryToScan = Console.ReadLine();

        if (string.IsNullOrEmpty(directoryToScan) || !Directory.Exists(directoryToScan))
        {
            Console.WriteLine("Invalid directory. Exiting.");
            return;
        }
        else
        {
            Console.Clear();
        }

        var maliciousFiles = ScanDirectory(directoryToScan);

        if (maliciousFiles.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Potentially malicious files found, please be careful ");
            Console.ResetColor();
            Console.WriteLine();
            foreach (var (filePath, patterns) in maliciousFiles)
            {
                Console.WriteLine($"File : {filePath}");
                Console.WriteLine();
                foreach (var pattern in patterns)
                {
                    if (IsHighRiskPattern(pattern))
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                    }
                    else if (IsLowerRiskPattern(pattern))
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.White;
                    }
                    Console.WriteLine($"Suspicious pattern found : {pattern}");
                    Console.ResetColor();
                }
                Console.WriteLine();
            }
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("No potentially malicious files found.");
            Console.ResetColor();
        }
    }

    static List<(string FilePath, List<string> Patterns)> ScanDirectory(string directory)
    {
        var maliciousFiles = new List<(string, List<string>)>();

        foreach (var filePath in Directory.GetFiles(directory, "*.*", SearchOption.AllDirectories))
        {
            if (filePath.EndsWith(".csproj") || filePath.EndsWith(".sln") || filePath.EndsWith(".vcxproj") || filePath.EndsWith(".proj") || filePath.EndsWith(".props") || filePath.EndsWith(".targets"))
            {
                var isMalicious = ScanFile(filePath);
                if (isMalicious.Item1)
                {
                    maliciousFiles.Add((filePath, isMalicious.Item2));
                }
            }
        }

        return maliciousFiles;
    }

    static (bool, List<string>) ScanFile(string filePath)
    {
        var content = File.ReadAllText(filePath);
        var detectedPatterns = new List<string>();

        foreach (var pattern in HighRiskPatterns)
        {
            if (pattern.IsMatch(content))
            {
                detectedPatterns.Add(pattern.ToString());
            }
        }

        foreach (var pattern in LowerRiskPatterns)
        {
            if (pattern.IsMatch(content))
            {
                detectedPatterns.Add(pattern.ToString());
            }
        }

        return (detectedPatterns.Count > 0, detectedPatterns);
    }

    static bool IsHighRiskPattern(string pattern)
    {
        return HighRiskPatterns.Exists(hp => hp.ToString() == pattern);
    }

    static bool IsLowerRiskPattern(string pattern)
    {
        return LowerRiskPatterns.Exists(lr => lr.ToString() == pattern);
    }
}
