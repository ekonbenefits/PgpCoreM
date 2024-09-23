using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using PgpCoreM.Abstractions;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpCoreM
{
    public partial class PGP : IKeyAsync
    {
        public async Task GenerateKeyAsync(
            FileInfo publicKeyFileInfo,
            FileInfo privateKeyFileInfo,
            string username = null,
            string password = null,
            int sigType = PgpSignature.DefaultCertification,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0)
                {
                    await Task.Run(() => GenerateKey(publicKeyFileInfo, privateKeyFileInfo, username, password, sigType,
                         armor, emitVersion, keyExpirationInSeconds, signatureExpirationInSeconds));
                }

        public async Task GenerateKeyAsync(
            Stream publicKeyStream,
            Stream privateKeyStream,
            string username = null,
            string password = null,
            int sigType = PgpSignature.DefaultCertification,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0)
        {
            await Task.Run(() => GenerateKey(publicKeyStream, privateKeyStream, username, password, sigType,
                 armor, emitVersion, keyExpirationInSeconds, signatureExpirationInSeconds));
        }
    }
}
