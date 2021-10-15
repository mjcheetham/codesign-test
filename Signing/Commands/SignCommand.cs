using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Signing.Commands
{
    public class SignCommand : Command
    {
        public SignCommand() : base("sign", "Sign binaries and installer packages")
        {
            AddOption(
                new Option<string>(new[]{"--certificate", "-c"})
                {
                    IsRequired = true,
                    Description = "Thumbprint of an installed code-signing certificate",
                    ArgumentHelpName = "thumbprint"
                }
            );


            if (OperatingSystem.IsWindows())
            {
                AddOption(
                    new Option<string>(new[]{"--hash", "-h"})
                    {
                        Description = "Hash algorithm to use for signing",
                        ArgumentHelpName = "alg"
                    }.FromAmong("sha1", "sha256")
                );

                AddOption(
                    new Option<string>(new[]{"--timestamp-url", "-t"})
                    {
                        Description = "Timestamp server URL",
                        ArgumentHelpName = "url"
                    }
                );

                AddOption(
                    new Option<string>(new[]{"--architecture", "-a"})
                    {
                        IsRequired = true,
                        Description = "Architecture of the files to sign",
                        ArgumentHelpName = "arch",
                    }
                );
            }

            AddArgument(
                new Argument<string>("files")
                {
                    Arity = ArgumentArity.OneOrMore,
                    Description = "Set of files to sign"
                }
            );

            Handler = CommandHandler.Create<string, string, string, string, string[]>(ExecuteAsync);
        }

        private static async Task<int> ExecuteAsync(
            string certificate, string timestampUrl, string architecture, string hash, string[] files)
        {
            await Console.Error.WriteLineAsync($"Certificate: {certificate}");
            await Console.Error.WriteLineAsync($"Files: [{string.Join(", ", files)}]");

            // Resolve the certificate from the thumbprint
            X509Certificate2 x509Cert = X509CertificateEx.CreateFromThumbprint(certificate);
            if (x509Cert is null)
            {
                await Console.Error.WriteLineAsync($"error: unable to locate certificate with thumbprint '{certificate}'");
                return -1;
            }

            await Console.Error.WriteLineAsync($"Resolved certificate: {x509Cert.Subject}");

            if (OperatingSystem.IsWindows())
            {
                return await ExecuteSignToolAsync(x509Cert, timestampUrl, architecture, hash, files);
            }

            if (OperatingSystem.IsMacOS())
            {
                return await ExecuteCodeSignAsync(x509Cert, files);
            }

            await Console.Error.WriteLineAsync("error: signing operation not supported on this platform");
            return -1;
        }

        [SupportedOSPlatform("windows")]
        private static async Task<int> ExecuteSignToolAsync(
            X509Certificate2 certificate, string timestampUrl, string architecture, string hash, string[] files)
        {
            var argsBase = new StringBuilder("sign");
            argsBase.AppendFormat(" /sha1 \"{0}\"", certificate.Thumbprint);

            if (!string.IsNullOrWhiteSpace(hash))
            {
                argsBase.AppendFormat(" /fd \"{0}\"", hash);
            }

            if (!string.IsNullOrWhiteSpace(timestampUrl))
            {
                argsBase.AppendFormat(" /t \"{0}\"", timestampUrl);
            }

            string signToolPath = FindSignTool(architecture);
            if (signToolPath is null)
            {
                await Console.Error.WriteLineAsync($"error: failed to find signtool.exe for architecture '{architecture}'");
                return -1;
            }

            await Console.Error.WriteLineAsync($"Found signtool.exe: {signToolPath}");

            foreach (string file in files)
            {
                string args = $"{argsBase} \"{file}\"";

                int result = await ExecuteToolAsync(signToolPath, args);
                if (result != 0)
                {
                    await Console.Error.WriteLineAsync($"error: failed to sign {file} (exit={result})");
                    return -1;
                }
            }

            return 0;
        }

        [SupportedOSPlatform("macos")]
        private static async Task<int> ExecuteCodeSignAsync(X509Certificate2 certificate, string[] files)
        {
            string codeSignPath = "/usr/bin/codesign";

            var argsBase = new StringBuilder();
            argsBase.AppendFormat("-s \"{0}\"", certificate.Thumbprint);
            argsBase.Append(" --options runtime"); // enable hardened runtime
            argsBase.Append(" --force"); // overwrite any existing signatures

            foreach (string file in files)
            {
                string args = $"{argsBase} \"{file}\"";

                int result = await ExecuteToolAsync(codeSignPath, args);
                if (result != 0)
                {
                    await Console.Error.WriteLineAsync($"error: failed to sign {file} (exit={result})");
                    return -1;
                }
            }

            return 0;
        }

        private static async Task<int> ExecuteToolAsync(string toolPath, string toolArgs)
        {
            var psi = new ProcessStartInfo(toolPath, toolArgs);
            using var proc = new Process { StartInfo = psi };

            await Console.Error.WriteLineAsync($"Executing: {psi.FileName} {psi.Arguments}");

            proc.Start();
            await proc.WaitForExitAsync();

            return proc.ExitCode;
        }

        [SupportedOSPlatform("windows")]
        private static string FindSignTool(string architecture)
        {
            /* We're looking for signtool.exe that is part of the Windows SDK.
             * We can find the SDK installation locations in the registry under the key:
             *
             *  HKLM\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v10.0\InstallationFolder (64-bit)
             *
             *  HKLM\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0\InstallationFolder (32-bit)
             *
             * Right now we only expect to be run with the Windows 10 SDK (any version) and select
             * the latest version.
             */

            string rootKey = Environment.Is64BitOperatingSystem
                ? @"SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v10.0"
                : @"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0";

            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(rootKey);
            object value = key?.GetValue("InstallationFolder");

            if (value is string installationFolder)
            {
                string binDir = Path.Combine(installationFolder, "bin");

                var sdkDirs = Directory.GetDirectories(binDir, "10.*");
                var sdkVersions = new Dictionary<Version, string>();
                foreach (string sdkDir in sdkDirs)
                {
                    string name = Path.GetFileName(sdkDir);
                    if (Version.TryParse(name, out Version version))
                    {
                        sdkVersions[version] = sdkDir;
                    }
                }

                foreach ((_, string dir) in sdkVersions.OrderByDescending(x => x.Key))
                {
                    string signTool = Path.Combine(dir, architecture, "signtool.exe");
                    if (File.Exists(signTool))
                    {
                        return signTool;
                    }
                }
            }

            return null;
        }
    }
}
