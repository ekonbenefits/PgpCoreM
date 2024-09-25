using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCoreM.Abstractions;

namespace PgpCoreM;

public class PgpCoreKeySet : IEncryptionKeys
{
    //Decrypted Secret keys
    private Dictionary<long, PgpPrivateKey> _privateKeys = new();
    private Dictionary<long, PgpSecretKey> _secretKeys = new();
    private Dictionary<long, PgpPublicKey> _publicKeys = new();

    public int AddSecretKeys(Stream privateKeyRing, string password)
    {
        var bundle = Utilities.ReadSecretKeyRingBundle(privateKeyRing);
        var count = 0;
        foreach(var secretKey in bundle.GetKeyRings().SelectMany(it=>it.GetSecretKeys()))
        {
            _secretKeys.Add(secretKey.PublicKey.KeyId, secretKey);
            _privateKeys.Add(secretKey.PublicKey.KeyId, secretKey.ExtractPrivateKey(password?.ToCharArray()));
            _publicKeys.Add(secretKey.PublicKey.KeyId, secretKey.PublicKey);
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
            count++;
        }
        return count;
    }

    public long SigningKeyId
    {
        get;
        set;
    }

    public long[] EncryptionKeyIds
    {
        get;
        set;
    }


    public PgpPublicKey FindPublicKey(long keyId)
    {
        if (_publicKeys.TryGetValue(keyId, out var publicKey))
        {
            return publicKey;
        }
        return null;
    }

    public (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? FindSecretKey(long keyId)
    {
        if (_privateKeys.TryGetValue(keyId, out var priKey) && _secretKeys.TryGetValue(keyId, out var secKey))
        {
            return (priKey, secKey);
        }

        return null;
    }
}