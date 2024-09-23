using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.IO;
using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Bzip2;
using PgpCoreM.Abstractions;

namespace PgpCoreM
{
    public partial class PGP : IKeySync
    {
        public void GenerateKey(
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
            if (publicKeyFileInfo == null)
                throw new ArgumentException("PublicKeyFileInfo");
            if (privateKeyFileInfo == null)
                throw new ArgumentException("PrivateKeyFileInfo");

            using Stream pubs = publicKeyFileInfo.Create();
            using Stream pris = privateKeyFileInfo.Create();
            GenerateKey(pubs, pris,  username, password, sigType, armor, emitVersion,
                keyExpirationInSeconds, signatureExpirationInSeconds);
        }

        public void GenerateKey(
       
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
            username ??= string.Empty;



            IAsymmetricCipherKeyPairGenerator kpgSign;
            IAsymmetricCipherKeyPairGenerator kpgEncrypt;

            int algStrength = PublicKeyAlgorithm switch
            {
                AsymmetricAlgorithm.Rsa => SecurityStrengthInBits switch
                {
                    128 => 2048,
                    192 => 3072,
                    256 => 4096,
                    _ => 2048
                },
                _ => SecurityStrengthInBits
            };

            switch (PublicKeyAlgorithm)
            {
              
                case AsymmetricAlgorithm.Ec25519:
                    kpgSign = new ECKeyPairGenerator();
                    kpgSign.Init(new KeyGenerationParameters(PGP.SecRandom, algStrength));

                    kpgEncrypt = new X25519KeyPairGenerator();
                    kpgEncrypt.Init(new KeyGenerationParameters(PGP.SecRandom, algStrength));
                    break;
                case AsymmetricAlgorithm.Rsa:
                default:
                    kpgSign = new RsaKeyPairGenerator();
                    kpgSign.Init(new KeyGenerationParameters(PGP.SecRandom, algStrength));

                    kpgEncrypt = new RsaKeyPairGenerator();
                    kpgEncrypt.Init(new KeyGenerationParameters(PGP.SecRandom, algStrength));
                    break;
            }

            var (publicKeySignAlgo, publicKeyEncAlgo) = PublicKeyAlgorithm switch
            {
                AsymmetricAlgorithm.Ec25519 => (PublicKeyAlgorithmTag.ECDsa, PublicKeyAlgorithmTag.ECDH),
                AsymmetricAlgorithm.Rsa => (PublicKeyAlgorithmTag.RsaSign, PublicKeyAlgorithmTag.RsaEncrypt),
                _ => throw new NotSupportedException("Unsupported public key algorithm")
            };
          

            

            PgpKeyPair masterKey = new PgpKeyPair(publicKeySignAlgo, kpgSign.GenerateKeyPair(), DateTime.UtcNow);
            PgpKeyPair encKey = new PgpKeyPair(publicKeyEncAlgo, kpgEncrypt.GenerateKeyPair(), DateTime.UtcNow);

            PgpSignatureSubpacketGenerator signHashGen = new PgpSignatureSubpacketGenerator();
            signHashGen.SetKeyFlags(false, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign);
            signHashGen.SetPreferredCompressionAlgorithms(false, Array.ConvertAll(PreferredCompressionAlgorithms, item => (int)item));
            signHashGen.SetPreferredHashAlgorithms(false, Array.ConvertAll(PreferredHashAlgorithms, item => (int)item));
            signHashGen.SetPreferredSymmetricAlgorithms(false, Array.ConvertAll(PreferredSymmetricKeyAlgorithms, item => (int)item));
            signHashGen.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
            signHashGen.SetKeyExpirationTime(false, keyExpirationInSeconds);
            signHashGen.SetSignatureExpirationTime(false, signatureExpirationInSeconds);

            PgpKeyRingGenerator keyRingGen = new PgpKeyRingGenerator(
                sigType,
                masterKey,
                username,
                SymmetricKeyAlgorithm,
                HashAlgorithm,
                password?.ToCharArray(),
                HashAlgorithm == HashAlgorithmTag.Sha1,
                signHashGen.Generate(),
                null,
                PGP.SecRandom);

            PgpSignatureSubpacketGenerator encHashGen = new PgpSignatureSubpacketGenerator();
            encHashGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            encHashGen.SetPreferredCompressionAlgorithms(false, Array.ConvertAll(PreferredCompressionAlgorithms, item => (int)item));
            encHashGen.SetPreferredHashAlgorithms(false, Array.ConvertAll(PreferredHashAlgorithms, item => (int)item));
            encHashGen.SetPreferredSymmetricAlgorithms(false, Array.ConvertAll(PreferredSymmetricKeyAlgorithms, item => (int)item));
            encHashGen.SetFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
            encHashGen.SetKeyExpirationTime(false, keyExpirationInSeconds);
            encHashGen.SetSignatureExpirationTime(false, signatureExpirationInSeconds);
            

            keyRingGen.AddSubKey(encKey, encHashGen.Generate(), null);
            

            PgpSecretKeyRing secretKeyRing = keyRingGen.GenerateSecretKeyRing();

            ExportKeyPair(privateKeyStream, publicKeyStream, secretKeyRing.GetSecretKey(), armor, emitVersion);
        }
    }
}
