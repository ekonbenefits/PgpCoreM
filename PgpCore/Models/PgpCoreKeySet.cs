using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCoreM.Abstractions;

namespace PgpCoreM;

public class PgpCoreKeySet : IKeySet
{
    //Decrypted Secret keys
    private Dictionary<long, PgpPrivateKey> _privateKeys = new();
    private Dictionary<long, PgpSecretKey> _secretKeys = new();
    private Dictionary<long, PgpPublicKey> _publicKeys = new();
    private HashSet<long> _encryptKeyIds = new();

    public int AddSecretKeys(Stream privateKeyRing, string password)
    {
        var bundle = Utilities.ReadSecretKeyRingBundle(privateKeyRing);
        var count = 0;
        foreach(var secretKey in bundle.GetKeyRings().SelectMany(it=>it.GetSecretKeys()))
        {
            _secretKeys.Add(secretKey.PublicKey.KeyId, secretKey);

            if (secretKey.IsMasterKey && SignKeyId == 0  && secretKey.PublicKey.IsSigningKey())
            {
                SignKeyId = secretKey.KeyId;
            }

            _privateKeys.Add(secretKey.PublicKey.KeyId, secretKey.ExtractPrivateKey(password?.ToCharArray()));
            _publicKeys.Add(secretKey.PublicKey.KeyId, secretKey.PublicKey);

            if (secretKey.PublicKey.IsEncryptionKey)
            {
                _encryptKeyIds.Add(secretKey.PublicKey.KeyId);
            }

            count++;
        }

        return count;
    }

    public int AddPublicKeys(Stream publicKeyRing)
    {
        var bundle = Utilities.ReadAllKeyRings(publicKeyRing);
        var count = 0;
        foreach (var publicKey in bundle.SelectMany(it => it.GetPublicKeys()))
        {
            _publicKeys.Add(publicKey.KeyId, publicKey);

            if (publicKey.IsEncryptionKey)
            {
                _encryptKeyIds.Add(publicKey.KeyId);
            }


            count++;
        }
        return count;
    }

    public long SignKeyId
    {
        get;
        set;
    }

    public long[] EncryptKeyIds
    {
        get;
        set;
    }


    public PgpPublicKey FindPublicEncryptKey(long keyId)
    {
        if (_publicKeys.TryGetValue(keyId, out var publicKey)  && publicKey.IsEncryptionKey)
        {
            return publicKey;
        }
        return null;
    }

    public PgpPublicKey FindPublicVerifyKey(long keyId)
    {
        if (_publicKeys.TryGetValue(keyId, out var publicKey) && publicKey.IsSigningKey()) 
        {
            return publicKey;
        }
        return null;
    }

    public (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? FindSecretDecryptKey(long keyId)
    {
        if (_privateKeys.TryGetValue(keyId, out var priKey)
            && _secretKeys.TryGetValue(keyId, out var secKey)
            && secKey.PublicKey.IsEncryptionKey)
        {
            return (priKey, secKey);
        }

        return null;
    }

    public (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? FindSecretSignKey(long keyId)
    {
        if (_privateKeys.TryGetValue(keyId, out var priKey)
            && _secretKeys.TryGetValue(keyId, out var secKey)
            && secKey.PublicKey.IsSigningKey()
            )
        {
            return (priKey, secKey);
        }

        return null;
    }
}