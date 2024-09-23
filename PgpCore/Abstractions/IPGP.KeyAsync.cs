using Org.BouncyCastle.Bcpg;
using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpCoreM.Abstractions
{
    public interface IKeyAsync
    {
        public Task GenerateKeyAsync(
            FileInfo publicKeyFileInfo,
            FileInfo privateKeyFileInfo,
            string username = null,
            string password = null,
            int sigType = PgpSignature.DefaultCertification,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0);

        public Task GenerateKeyAsync(
            Stream publicKeyStream,
            Stream privateKeyStream,
           
            string username = null,
            string password = null,
            int sigType = PgpSignature.DefaultCertification,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0);
    }
}
