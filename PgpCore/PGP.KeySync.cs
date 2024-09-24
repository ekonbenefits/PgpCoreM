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

            var pubKeyAlg = PublicKeyAlgorithm;
            var secStrength = SecurityStrengthInBits;

            var keyParams = Utilities.AsymmetricKeyGeneratorParams(pubKeyAlg, secStrength);

            switch (PublicKeyAlgorithm)
            {
              
                case AsymmetricAlgorithm.Ec25519:
                    kpgSign = new Ed25519KeyPairGenerator();
                    kpgSign.Init(keyParams.signParams);

                    kpgEncrypt = new X25519KeyPairGenerator();
                    kpgEncrypt.Init(keyParams.encryptParameters);
                    break;
                case AsymmetricAlgorithm.Ec:
                    kpgSign = new ECKeyPairGenerator();
                    kpgSign.Init(keyParams.signParams);

                    kpgEncrypt = new ECKeyPairGenerator();
                    kpgEncrypt.Init(keyParams.encryptParameters);
                    break;
                case AsymmetricAlgorithm.Rsa:
                default:
                    kpgSign = new RsaKeyPairGenerator();
                    kpgSign.Init(keyParams.signParams);

                    kpgEncrypt = new RsaKeyPairGenerator();
                    kpgEncrypt.Init(keyParams.encryptParameters);
                    break;
            }

            var (publicKeySignAlgo, publicKeyEncAlgo) = PublicKeyAlgorithm switch
            {
                AsymmetricAlgorithm.Ec 
                    => (PublicKeyAlgorithmTag.ECDsa, PublicKeyAlgorithmTag.ECDH),
                AsymmetricAlgorithm.Ec25519
                    => (PublicKeyAlgorithmTag.EdDsa, PublicKeyAlgorithmTag.ECDH),
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
                true, //for key ids
                signHashGen.Generate(),
                null,PGP.SecRandom);

            PgpSignatureSubpacketGenerator encHashGen = new PgpSignatureSubpacketGenerator();
            encHashGen.SetKeyFlags(false, PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage);
            encHashGen.SetKeyExpirationTime(false, keyExpirationInSeconds);
            encHashGen.SetSignatureExpirationTime(false, signatureExpirationInSeconds);

            keyRingGen.AddSubKey(encKey, encHashGen.Generate(), null, HashAlgorithm);
            

            var secretKeyRing = keyRingGen.GenerateSecretKeyRing();
            var pubKeyRing = keyRingGen.GeneratePublicKeyRing();

            ExportKeyPair(privateKeyStream, publicKeyStream, secretKeyRing, pubKeyRing, armor, emitVersion);
        }

   
    }
}
