using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpCoreM.Abstractions
{
    public interface IKeySync
    {
        void GenerateKey(
            FileInfo publicKeyFileInfo,
            FileInfo privateKeyFileInfo,
            string username = null,
            string password = null,
            int sigType = PgpSignature.DefaultCertification,
            bool armor = true,
            bool emitVersion = true,
            long keyExpirationInSeconds = 0,
            long signatureExpirationInSeconds = 0);

        void GenerateKey(
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
