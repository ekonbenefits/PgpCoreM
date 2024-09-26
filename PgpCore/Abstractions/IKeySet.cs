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
    public interface IKeySet
    {
     
        long SignKeyId { get;  }
        long[] EncryptKeyIds { get;  }
    

        PgpPublicKey FindPublicEncryptKey(long keyId);

        PgpPublicKey FindPublicVerifyKey(long keyId);

        (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? FindSecretDecryptKey(long keyId);
        (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? FindSecretSignKey(long keyId);
    }


    public static class ExtIEncryptionKeys
    {
        public static IEnumerable<PgpPublicKey> GetPublicEncryptKeys(this IKeySet keys)
        {
         
            foreach (var keyIds in keys.EncryptKeyIds)
            {
                var publicKey = keys.FindPublicEncryptKey(keyIds);
                if (publicKey != null)
                {
                    yield return publicKey;
                }
            }
        }
    }
}