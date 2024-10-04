using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using PgpCoreM.Models;
using Xunit;
using System.Threading.Tasks;
using PgpCoreM.Tests.UnitTests.Encrypt;
using Xunit.Abstractions;

namespace PgpCoreM.Tests.UnitTests.Decrypt
{




    public class DecryptSync_File : TestBase
    {

        private readonly ITestOutputHelper output;

        public DecryptSync_File(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptBinaryEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetCompressionAlgorithimTags))]
        public void Decrypt_DecryptEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetCompressionAlgorithimTags))]
        public void Decrypt_DecryptBinaryEncryptedCompressedMessage_ShouldDecryptMessage(CompressionAlgorithmTag compressionAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = compressionAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetHashAlgorithimTags))]
        public void Decrypt_DecryptEncryptedWithSpecifiedHashAlgorithim_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithm = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetHashAlgorithimTags))]
        public void Decrypt_DecryptBinaryEncryptedWithSpecifiedHashAlgorithim_ShouldDecryptMessage(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                HashAlgorithm = hashAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetSymmetricAlgorithimTags))]
        public void Decrypt_DecryptEncryptedWithSpecifiedSymetricKeyAlgorithim_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);
            PgpInspectResult pgpInspectResult = pgpDecrypt.Inspect(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            pgpInspectResult.SymmetricKeyAlgorithm.Should().Be(symmetricKeyAlgorithmTag);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(GetSymmetricAlgorithimTags))]
        public void Decrypt_DecryptBinaryEncryptedWithSpecifiedSymetricKeyAlgorithim_ShouldDecryptMessage(SymmetricKeyAlgorithmTag symmetricKeyAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = symmetricKeyAlgorithmTag
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);
            PgpInspectResult pgpInspectResult = pgpDecrypt.Inspect(testFactory.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().NotStartWith("-----BEGIN PGP MESSAGE-----");
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            pgpInspectResult.SymmetricKeyAlgorithm.Should().Be(symmetricKeyAlgorithmTag);

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Decrypt_DecryptEncryptedWithNullSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Null
            };

            // Act
            var ex = Assert.Throws<PgpException>(() => pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<PgpException>();
                ex.Message.Should().Be("unknown symmetric algorithm: Null");
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Decrypt_DecryptEncryptedWithSaferSymetricKeyAlgorithim_ShouldThrowException()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Safer
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            var ex = Assert.Throws<SecurityUtilityException>(() => pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<SecurityUtilityException>();
                ex.Message.Should().Be("Algorithm SAFER not recognised.");
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptEncryptedWithMultipleKeys_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpEncrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName1);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo, out var originalFileName2);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory2.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                File.ReadAllText(testFactory2.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName1);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName2);


            }

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }


        [Fact]
        public void Decrypt_DecryptEncryptedWithMultipleKeys_NewKeystore()
        {
            // Arrange
            var sender = new TestFactory();
            var receiver = new TestFactory();

            sender.Arrange(KeyType.Generated, FileType.Known);
            receiver.Arrange(KeyType.Generated, FileType.Known);



            var crypterSet = new PgpCoreKeySet();
            crypterSet.AddPublicKeys(receiver.PublicKeyStream);
            crypterSet.AddPublicKeys(sender.PublicKeyStream);
            crypterSet.AddSecretKeys(sender.PrivateKeyStream, sender.Password);

            var decrypterset = new PgpCoreKeySet();
            decrypterset.AddPublicKeys(sender.PublicKeyStream);
            decrypterset.AddSecretKeys(receiver.PrivateKeyStream, receiver.Password);


            PGP pgpEncrypt = new PGP(crypterSet);
            PGP pgpDecrypt = new PGP(decrypterset);

            // Act
            pgpEncrypt.EncryptAfterSign(sender.ContentFileInfo, receiver.EncryptedContentFileInfo);
            pgpDecrypt.DecryptAndVerify(receiver.EncryptedContentFileInfo, receiver.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                receiver.EncryptedContentFileInfo.Exists.Should().BeTrue();
                receiver.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(receiver.DecryptedContentFileInfo.FullName).Should().Be(sender.Content);
                originalFileName.Should().Be(sender.ContentFileInfo.Name);


            }
            output.WriteLine(receiver.EncryptedContentFileInfo.FullName);
            output.WriteLine(receiver.PrivateKeyFileInfo.FullName);
            output.WriteLine(sender.PublicKeyFileInfo.FullName);
            // Teardown
          //  sender.Teardown();
          //  receiver.Teardown();
        }


        [Fact(Skip="For Debugging Purposes")]
        public void Decrypt_DecryptEncryptedWithMultipleKeys_NewKeystoreManual()
        {
            // Arrange
            var sender = new TestFactory();
     

            sender.Arrange(KeyType.Known, FileType.Known);

            var receiverPublicInfo = new FileInfo(@"G:\pgp-scratch\receive-public.asc");
            var receiverPrivateInfo = new FileInfo(@"G:\pgp-scratch\receive-private.asc");
            var receiverPrivatePass = new FileInfo(@"G:\pgp-scratch\receive-private-pass.txt");
            var manualSenderPublicKey =new FileInfo(@"G:\pgp-scratch\send-public.asc");

            var decrypterset = new PgpCoreKeySet();
            {
                using var readStream = receiverPrivateInfo.OpenRead();
                using var sendStream = manualSenderPublicKey.OpenRead();
                decrypterset.AddPublicKeys(sendStream);
                decrypterset.AddSecretKeys(readStream, File.ReadAllText(receiverPrivatePass.FullName));
            }


        
            PGP pgpDecrypt = new PGP(decrypterset);


            var manualEncryptedFileInfo = new FileInfo(@"G:\pgp-scratch\test.csv.gpg");
            // Act
            // pgpEncrypt.EncryptAfterSign(sender.ContentFileInfo, sender.EncryptedContentFileInfo);
            pgpDecrypt.DecryptAndVerify(manualEncryptedFileInfo, sender.DecryptedContentFileInfo, out var originalFileName);
            

            var content = File.ReadAllText(@"G:\pgp-scratch\test.csv");
            // Assert
            using (new AssertionScope())
            {
                sender.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(sender.DecryptedContentFileInfo.FullName).Should().Be(content);
                //originalFileName.Should().Be("test.csv");
            }
            output.WriteLine(sender.EncryptedContentFileInfo.FullName);
            output.WriteLine(sender.PublicKeyFileInfo.FullName);
            // Teardown
            //  sender.Teardown();
            //  receiver.Teardown();
        }



        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptSignedAndEncryptedMessage_ShouldDecryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionAndSigningKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptionAndSigningKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncryptAndSign.EncryptAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptUnencryptedMessage_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            File.WriteAllText(testFactory.ContentFileInfo.FullName, testFactory.Content);

            // Act
            var ex = Assert.Throws<ArgumentException>(() => pgpDecrypt.Decrypt(testFactory.ContentFileInfo, testFactory.DecryptedContentFileInfo, out _));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<ArgumentException>();
                ex.Message.Should().StartWith("Failed to detect encrypted content format.");
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Decrypt_DecryptEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<ArgumentException>(() => pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _));

            // Assert
            using (new AssertionScope())
            {
                ex.Should().BeAssignableTo<ArgumentException>();
                ex.Message.Should().Be("Secret key for message not found.");
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Decrypt_DecryptEncryptedMessageWithoutPassword_ShouldDecryptMessage()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);
            string password = string.Empty;

            PGP pgpKeys = new PGP();
            pgpKeys.GenerateKey(
                testFactory.PublicKeyFileInfo,
                testFactory.PrivateKeyFileInfo,
                testFactory.UserName,
                password
                );

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.Decrypt(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                testFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(testFactory.DecryptedContentFileInfo.FullName).Should().Be(testFactory.Content);
                testFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptAndVerify_DecryptSignedAndEncryptedMessage_ShouldDecryptAndVerifyMessage(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();

            encryptTestFactory.Arrange(keyType, FileType.Known);
            signTestFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyFileInfo, signTestFactory.PrivateKeyFileInfo, signTestFactory.Password);

            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            pgpEncryptAndSign.EncryptAfterSign(encryptTestFactory.ContentFileInfo, encryptTestFactory.EncryptedContentFileInfo);
            pgpDecryptAndVerify.DecryptAndVerify(encryptTestFactory.EncryptedContentFileInfo, encryptTestFactory.DecryptedContentFileInfo, out var originalFileName);

            // Assert
            using (new AssertionScope())
            {
                encryptTestFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                encryptTestFactory.DecryptedContentFileInfo.Exists.Should().BeTrue();
                File.ReadAllText(encryptTestFactory.DecryptedContentFileInfo.FullName).Should().Be(encryptTestFactory.Content);
                encryptTestFactory.ContentFileInfo.Name.Should().Be(originalFileName);

            }

            // Teardown
            encryptTestFactory.Teardown();
            signTestFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptAndVerify_DecryptSignedAndEncryptedMessageWithWrongKey_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory encryptTestFactory = new TestFactory();
            TestFactory signTestFactory = new TestFactory();
            var signTestFactory2 = new TestFactory();

            encryptTestFactory.Arrange(keyType, FileType.Known);
            signTestFactory.Arrange(KeyType.Generated, FileType.Known);
            signTestFactory2.Arrange(KeyType.Generated, FileType.Known);


            EncryptionKeys encryptAndSignKeys = new EncryptionKeys(encryptTestFactory.PublicKeyFileInfo, signTestFactory.PrivateKeyFileInfo, signTestFactory.Password);
            EncryptionKeys decryptAndVerifyKeys = new EncryptionKeys(signTestFactory2.PublicKeyFileInfo, encryptTestFactory.PrivateKeyFileInfo, encryptTestFactory.Password);
            PGP pgpEncryptAndSign = new PGP(encryptAndSignKeys);
            PGP pgpDecryptAndVerify = new PGP(decryptAndVerifyKeys);

            // Act
            pgpEncryptAndSign.EncryptAfterSign(encryptTestFactory.ContentFileInfo, encryptTestFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<PgpException>(() => pgpDecryptAndVerify.DecryptAndVerify(encryptTestFactory.EncryptedContentFileInfo, encryptTestFactory.DecryptedContentFileInfo, out _));

            // Assert
            using (new AssertionScope())
            {
                encryptTestFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                ex.Should().BeAssignableTo<PgpException>();
                ex.Message.Should().Be("Failed to verify file.");
            }

            // Teardown
            encryptTestFactory.Teardown();
            signTestFactory.Teardown();
        }
    }
}
