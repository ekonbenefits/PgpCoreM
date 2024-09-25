using System;
using System.Collections.Generic;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCoreM.Models;

namespace PgpCoreM
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


    public static class ExtIEncryptionKeys
    {
        public static IEnumerable<PgpPublicKey> GetPublicKeys(this IEncryptionKeys keys)
        {
         
            foreach (var keyIds in keys.EncryptionKeyIds)
            {
                var publicKey = keys.FindPublicKey(keyIds);
                if (publicKey != null)
                {
                    yield return publicKey;
                }
            }
        }
    }
}