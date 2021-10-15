using System;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Signing.Commands
{
    public class NotarizeCommand : Command
    {
        public NotarizeCommand() : base("notarize", "Notarize an application bundle or installer package")
        {
            AddOption(
                new Option<string>(new[]{"--apple-id"})
                {
                    IsRequired = true,
                    Description = "Apple ID account/email",
                    ArgumentHelpName = "id"
                });

            AddOption(
                new Option<string>(new[]{"--password"})
                {
                    IsRequired = true,
                    Description = "Apple ID password"
                });

            AddArgument(
                new Argument<FileInfo>("file")
                {
                    Arity = ArgumentArity.ExactlyOne,
                    Description = "Application bundle or installer package to notarize"
                }
            );

            Handler = CommandHandler.Create<string, string, FileInfo>(ExecuteAsync);
        }

        private static async Task<int> ExecuteAsync(string appleId, string password, FileInfo file)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                await Console.Error.WriteLineAsync("error: notarization is only available on macOS platforms");
                return -1;
            }

            await Console.Error.WriteLineAsync($"Apple ID: {appleId}");
            await Console.Error.WriteLineAsync($"File: {file.Name}");

            return 0;
        }
    }
}
