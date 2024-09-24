using System;
using System.Collections.Generic;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCoreM.Models;

namespace PgpCoreM.Abstractions
{
    /// <summary>
    /// Encryption Keys
    /// 
    /// You can supply any or all of these, however, if PrivateKeys 
    /// are required Secret keys should also be supplied
    /// </summary>
    public interface IEncryptionKeys
    {
     
        long SigningKeyId { get;  }
        long[] EncryptionKeyIds { get;  }

        PgpPublicKey FindPublicKey(long keyId);

        (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? FindSecretKey(long keyId);
    }
}