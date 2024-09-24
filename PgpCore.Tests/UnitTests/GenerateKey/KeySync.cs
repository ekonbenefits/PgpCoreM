using FluentAssertions.Execution;
using FluentAssertions;
using Xunit;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;
using System;
using System.Collections.Generic;
using Org.BouncyCastle.Bcpg;
using Xunit.Abstractions;

namespace PgpCoreM.Tests.UnitTests.GenerateKey
{
    public class KeySync : TestBase
    {
        private readonly ITestOutputHelper output;

        public KeySync(ITestOutputHelper output) 
        {
            this.output = output;
        }

        [Theory]
        [MemberData(nameof(GetStrengthsAndAlgs))]
        public void GenerateKey_CreatePublicAndPrivateKeysWithKeyStrength_ShouldCreateKeysVariousStrength(int strength, AsymmetricAlgorithm alg)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP(strength, alg);


            output.WriteLine(testFactory.PublicKeyFileInfo.FullName);
            output.WriteLine(testFactory.PrivateKeyFileInfo.FullName);
            output.WriteLine(testFactory.UserName);
            output.WriteLine(testFactory.Password);


            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password
                );

            // Assert
            // Assert that the keys were created
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();
            }

            // Assert public key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PublicKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = publicKey = ReadPublicKey(publicKeyStream);
                    var startTime = DateTime.UtcNow;
                    // If we successfully read the public key without exceptions, it is considered valid
                    publicKey.Should().NotBeNull();
                    publicKey.Version.Should().Be(4);
                    publicKey.CreationTime.Should().BeBefore(startTime.Add(new TimeSpan(0, 0, 15 *  2 ^ (strength / 64 ))));
                    publicKey.IsEncryptionKey.Should().BeFalse();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(Utilities.AsymmetricStrength(pgp.PublicKeyAlgorithm, pgp.SecurityStrengthInBits));
                    publicKey.IsRevoked().Should().BeFalse();

                }
            }

            // Assert private key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PrivateKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
                {
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                    foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
                    {
                        foreach (PgpSecretKey k in kRing.GetSecretKeys())
                        {
                            if (k.IsSigningKey)
                            {
                                k.Should().NotBeNull();
                                k.IsSigningKey.Should().BeTrue();
                                k.IsMasterKey.Should().BeTrue();
                                k.KeyEncryptionAlgorithm.Should().Be(Utilities.GetSymmetricAlgorithm(pgp.SecurityStrengthInBits));

                            }
                        }
                    }
                }
            }
        }

        [Fact]
        public void GenerateKey_CreatePublicAndPrivateKeysWithoutVersion_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password,
                emitVersion: false
                );

            // Assert
            // Assert that the keys were created
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();
            }

            // Assert public key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PublicKeyFileInfo.FullName).Should().NotContain(VERSION);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = ReadPublicKey(publicKeyStream);
                    // If we successfully read the public key without exceptions, it is considered valid
                    publicKey.Should().NotBeNull();
                    publicKey.Version.Should().Be(4);
                    publicKey.CreationTime.Should().BeCloseTo(DateTime.UtcNow, new TimeSpan(0, 0, 10));
                    publicKey.IsEncryptionKey.Should().BeFalse();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(Utilities.AsymmetricStrength(pgp.PublicKeyAlgorithm, pgp.SecurityStrengthInBits));
                }

            }

            // Assert private key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PrivateKeyFileInfo.FullName).Should().NotContain(VERSION);

                using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
                {
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                    foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
                    {
                        foreach (PgpSecretKey k in kRing.GetSecretKeys())
                        {
                            if (k.IsSigningKey)
                            {
                                k.Should().NotBeNull();
                                k.IsSigningKey.Should().BeTrue();
                                k.IsMasterKey.Should().BeTrue();
                                k.KeyEncryptionAlgorithm.Should().Be(Utilities.GetSymmetricAlgorithm(pgp.SecurityStrengthInBits));
                            }
                        }
                    }
                }
            }
        }

        [Fact]
        public void GenerateKey_CreatePublicAndPrivateKeysWithExpiryDate_ShouldCreateKeysWithSpecifiedProperties()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange();
            PGP pgp = new PGP();

            // Act
            pgp.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                testFactory.Password,
                keyExpirationInSeconds: 60
                );

            // Assert
            // Assert that the keys were created
            using (new AssertionScope())
            {
                testFactory.PublicKeyFileInfo.Exists.Should().BeTrue();
                testFactory.PrivateKeyFileInfo.Exists.Should().BeTrue();
            }

            // Assert public key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PublicKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = ReadPublicKey(publicKeyStream);
                    // If we successfully read the public key without exceptions, it is considered valid
                    publicKey.Should().NotBeNull();
                    publicKey.Version.Should().Be(4);
                    publicKey.CreationTime.Should().BeCloseTo(DateTime.UtcNow, new TimeSpan(0, 0, 10));
                    publicKey.IsEncryptionKey.Should().BeFalse();
                    publicKey.IsMasterKey.Should().BeTrue();
                    publicKey.IsRevoked().Should().BeFalse();
                    publicKey.BitStrength.Should().Be(Utilities.AsymmetricStrength(pgp.PublicKeyAlgorithm, pgp.SecurityStrengthInBits));
                    publicKey.GetValidSeconds().Should().Be(60);
                }

            }

            // Assert private key properties
            using (new AssertionScope())
            {
                File.ReadAllText(testFactory.PrivateKeyFileInfo.FullName).Should().Contain(VERSION);

                using (Stream privateKeyStream = testFactory.PrivateKeyFileInfo.OpenRead())
                {
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                    foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
                    {
                        foreach (PgpSecretKey k in kRing.GetSecretKeys())
                        {
                            if (k.IsSigningKey)
                            {
                                k.Should().NotBeNull();
                                k.IsSigningKey.Should().BeTrue();
                                k.IsMasterKey.Should().BeTrue();
                                k.KeyEncryptionAlgorithm.Should().Be(Utilities.GetSymmetricAlgorithm(pgp.SecurityStrengthInBits));
                            }
                        }
                    }
                }
            }
        }
    }
}
