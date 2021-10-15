using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Signing
{
    public static class X509CertificateEx
    {
        private static readonly StoreLocation[] AllStoreLocations =
        {
            StoreLocation.CurrentUser,
            StoreLocation.LocalMachine
        };

        public static bool IsThumbprint(string thumbprint)
        {
            return Regex.IsMatch(thumbprint, "^[0-9a-f]{40}$", RegexOptions.IgnoreCase);
        }

        public static X509Certificate2 CreateFromThumbprint(string thumbprint)
        {
            foreach (StoreLocation location in AllStoreLocations)
            {
                using var store = new X509Store(location);
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection findResult = store.Certificates.Find(
                    X509FindType.FindByThumbprint, thumbprint, false);

                if (findResult.Count > 0)
                {
                    return findResult[0];
                }
            }

            return null;
        }
    }
}
