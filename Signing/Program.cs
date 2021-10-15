using System;
using System.CommandLine;
using System.Threading.Tasks;
using Signing.Commands;

namespace Signing
{
    public static class Program
    {
        public static async Task Main(string[] args)
        {
            var rootCmd = new RootCommand("Code signing toolkit");

            rootCmd.AddCommand(new SignCommand());

            if (OperatingSystem.IsMacOS())
            {
                rootCmd.AddCommand(new NotarizeCommand());
            }

            int result = await rootCmd.InvokeAsync(args);

            Environment.Exit(result);
        }
    }
}
