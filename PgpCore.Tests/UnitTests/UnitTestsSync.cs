using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions.Execution;
using FluentAssertions;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCoreM.Models;
using Xunit;

namespace PgpCoreM.Tests
{
    public class UnitTestsSync
    {
        #region File - FileInfo
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptFile_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptFile_CreateEncryptedFileWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, headers: headers);
            string encryptedContent = File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Comment: Test comment", encryptedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptFile_CreateEncryptedFileWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, headers: headers);
            string encryptedContent = File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Version: Test version", encryptedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void EncryptFile_CreateEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            pgp.HashAlgorithm = hashAlgorithmTag;

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignFile_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignFile_CreateSignedFileWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            pgp.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo, headers: headers);
            string signedContent = File.ReadAllText(testFactory.SignedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.Contains("Comment: Test comment", signedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignFile_CreateSignedFileWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            pgp.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo, headers: headers);
            string signedContent = File.ReadAllText(testFactory.SignedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.Contains("Version: Test version", signedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignFile_CreateClearSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.ClearSignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndVerifyFile_CreateClearSignedFileAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            pgpEncrypt.ClearSignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(pgpVerify.VerifyClearFile(testFactory.SignedContentFileInfo));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndDoNotVerifyFile_CreateClearSignedFileAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);
            EncryptionKeys encryptionKeysSign = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys encryptionKeysVerify = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(encryptionKeysSign);
            PGP pgpVerify = new PGP(encryptionKeysVerify);

            // Act
            pgpSign.ClearSignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.False(pgpVerify.VerifyClearFile(testFactory.SignedContentFileInfo));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFile_CreateEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFileAndSign_CreateEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptFileAndSign_CreateEncryptedAndSignedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFile_DecryptEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void DecryptFile_DecryptEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            pgpEncrypt.HashAlgorithm = hashAlgorithmTag;

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        ////[Theory]
        ////[InlineData(KeyType.Generated, FileType.GeneratedLarge)]
        ////public void DecryptLargeFile_DecryptEncryptedFile(KeyType keyType, FileType fileType)
        ////{
        ////    // Arrange
        ////    Arrange(keyType, fileType);
        ////    PGP pgp = new PGP(encryptionKeys);

        ////    // Act
        ////    pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, testFactory.PublicKeyFileInfo);
        ////    pgp.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, testFactory.PrivateKeyFilePath, testFactory.Password);

        ////    // Assert
        ////    Assert.True(testFactory.EncryptedContentFileInfo.Exists);
        ////    Assert.True(File.Exists(testFactory.DecryptedContentFileInfo));

        ////    // Teardown
        ////    Teardown();
        ////}

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFile_DecryptEncryptedFileWithMultipleKeys(KeyType keyType)
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
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpEncrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFile_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            pgp.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFile_DecryptSignedAndEncryptedFileWithMultipleKeys(KeyType keyType)
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
            pgpEncrypt.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpEncrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);
            pgpDecrypt.DecryptFile(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptUnsignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<PgpException>(() => pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo,
               testFactory.DecryptedContentFileInfo, out _));

            // Assert
            Assert.Equal("File was not signed.", ex.Message);
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(string.Empty, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }


        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = Assert.Throws<PgpException>(() => pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo,
               testFactory.DecryptedContentFileInfo, out _));

            // Assert
            Assert.Equal("Failed to verify file.", ex.Message);
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(string.Empty, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptSignedAndEncryptedAndCompressedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            pgp.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgp.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptFileAndVerify_DecryptSignedAndEncryptedFileDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            pgpDecrypt.DecryptFileAndVerify(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyFile_VerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyFile_DoNotVerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.EncryptFileAfterSign(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            bool verified = pgpDecrypt.VerifyFile(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyFile_VerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            pgp.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = pgp.VerifyFile(testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyFile_DoNotVerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            pgpEncrypt.SignFile(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = pgpDecrypt.VerifyFile(testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }
        #endregion File - FileInfo

        #region Stream
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStream_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptStream_CreateEncryptedFileWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream, headers: headers);

            string encryptedContent = File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Comment: Test comment", encryptedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptStream_CreateEncryptedFileWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream, headers: headers);

            string encryptedContent = File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Version: Test version", encryptedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignStream_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.SignStream(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignStream_CreateSignedStreamWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.SignStream(inputFileStream, outputFileStream, headers: headers);

            string signedContent = File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Comment: Test comment", signedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignStream_CreateSignedStreamWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.SignStream(inputFileStream, outputFileStream, headers: headers);

            string signedContent = File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Version: Test version", signedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStream_CreateEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<Stream> keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStreamAndSign_CreateEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStreamAfterSign(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptStreamAndSign_CreateEncryptedAndSignedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<Stream> keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStreamAfterSign(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptStream_DecryptEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpDecrypt.DecryptStream(inputFileStream, outputFileStream, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void DecryptStream_DecryptEncryptedStreamWithPreferredKey()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            long[] keyIdsInPublicKeyRing = encryptionKeys.PublicKeyRings.First().PgpPublicKeyRing.GetPublicKeys()
                .Where(key => key.IsEncryptionKey).Select(key => key.KeyId).ToArray();
            foreach (long keyId in keyIdsInPublicKeyRing)
            {
                // Act
                encryptionKeys.UseEncryptionKey(keyId);
                using (Stream inputFileStream = testFactory.ContentStream)
                using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                    pgpEncrypt.EncryptStream(inputFileStream, outputFileStream);

                using (Stream inputFileStream = testFactory.EncryptedContentStream)
                using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                    pgpDecrypt.DecryptStream(inputFileStream, outputFileStream, out _);

                // Assert
                Assert.True(testFactory.EncryptedContentFileInfo.Exists);
                Assert.True(testFactory.DecryptedContentFileInfo.Exists);
                Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            }
            Assert.True(keyIdsInPublicKeyRing.Length > 1);
            
            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptStream_DecryptEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<Stream> keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpEncrypt.DecryptStream(inputFileStream, outputFileStream, out _);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory2.DecryptedContentFileInfo.Create())
                pgpDecrypt.DecryptStream(inputFileStream, outputFileStream, out _);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptStream_DecryptSignedAndEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStreamAfterSign(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgp.DecryptStream(inputFileStream, outputFileStream, out _);

            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptStream_DecryptSignedAndEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<Stream> keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                pgpEncrypt.DecryptStream(inputFileStream, outputFileStream, out _);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory2.DecryptedContentFileInfo.Create())
                pgpDecrypt.DecryptStream(inputFileStream, outputFileStream, out _);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = pgpEncrypt.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(testFactory2.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.Equal(testFactory.Content, testFactory2.DecryptedContent.Trim());
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStreamAfterSign(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = pgp.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }
        
        [Fact]
        public void Verify_VerifyEncryptedAndSignedStreamForMultipleKeys()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            long[] keyIdsInPublicKeyRing = encryptionKeys.PublicKeyRings.First().PgpPublicKeyRing.GetPublicKeys()
                .Where(key => key.IsEncryptionKey).Select(key => key.KeyId).ToArray();
            foreach (long keyId in keyIdsInPublicKeyRing)
            {
                encryptionKeys.UseEncryptionKey(keyId);
                using (Stream inputFileStream = testFactory.ContentStream)
                using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                    pgp.EncryptStreamAfterSign(inputFileStream, outputFileStream);

                bool verified = false;

                using (Stream inputFileStream = testFactory.EncryptedContentStream)
                    verified = pgp.VerifyStream(inputFileStream);

                // Assert
                Assert.True(testFactory.EncryptedContentFileInfo.Exists);
                Assert.True(verified);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyStream);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptStreamAfterSign(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = pgpDecrypt.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                pgp.SignStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = pgp.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyStream, testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            bool verified = true;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                pgpEncrypt.SignStream(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = pgpDecrypt.VerifyStream(inputFileStream);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStreamRecipient(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream);

            PgpPublicKey pgpPublicKey = Utilities.ReadPublicKey(testFactory.PublicKeyStream);
            IEnumerable<long> recipients = pgp.GetStreamRecipients(testFactory.EncryptedContentStream);

            // Assert
            Assert.Equal(pgpPublicKey.KeyId, recipients.FirstOrDefault());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStreamRecipients(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<Stream> keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream);

            keys = new List<Stream>()
            {
                testFactory.PublicKeyStream,
                testFactory2.PublicKeyStream
            };

            List<PgpPublicKey> pgpPublicKeys = keys.Select(x => Utilities.ReadPublicKey(x)).ToList();
            IEnumerable<long> recipients = pgp.GetStreamRecipients(testFactory.EncryptedContentStream);

            // Assert
            Assert.All(recipients, recipient => Assert.Contains(pgpPublicKeys, x => recipient == x.KeyId));

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void VerifyStream_ThrowIfEncrypted()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.GeneratedMedium);
            
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream);
            
            // Act and Assert
            try
            {
                pgp.VerifyStream(testFactory.EncryptedContentStream, true);
                Assert.Fail("Expected exception not thrown");
            }
            catch (ArgumentException e)
            {
                Assert.Equal("Input is encrypted. Decrypt the input first.", e.Message);
            }
            finally
            {
                // Teardown
                testFactory.Teardown();
            }
        }

        #endregion Stream

        #region Armor
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptArmoredString_CreateEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptArmoredString_CreateEncryptedStringWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content, headers: headers);

            // Assert
            Assert.Contains("Comment: Test comment", encryptedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public void EncryptArmoredString_CreateEncryptedStringWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content, headers: headers);

            // Assert
            Assert.Contains("Version: Test version", encryptedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void EncryptArmoredString_CreateEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);
            pgp.HashAlgorithm = hashAlgorithmTag;

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignArmoredString_CreateSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = pgp.SignArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignArmoredString_CreateSignedStringWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            string signedContent = pgp.SignArmoredString(testFactory.Content, headers: headers);

            // Assert
            Assert.NotNull(signedContent);
            Assert.Contains("Comment: Test comment", signedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void SignArmoredString_CreateSignedStringWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            string signedContent = pgp.SignArmoredString(testFactory.Content, headers: headers);
            Assert.Contains("Version: Test version", signedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", signedContent);

            // Assert
            Assert.NotNull(signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignArmoredString_CreateClearSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = pgp.ClearSignArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(clearSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndVerifyArmoredString_CreateClearSignedStringAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = pgp.ClearSignArmoredString(testFactory.Content);

            // Assert
            Assert.True(pgp.VerifyClearArmoredString(clearSignedContent));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndDoNotVerifyArmoredString_CreateClearSignedStringAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string clearSignedContent = pgpEncrypt.ClearSignArmoredString(testFactory.Content);

            // Assert
            Assert.False(pgpDecrypt.VerifyClearArmoredString(clearSignedContent));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndVerifyArmoredString_CreateClearSignedStringAndVerifyAndRead(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = pgp.ClearSignArmoredString(testFactory.Content);
            VerificationResult result = pgp.VerifyAndReadClearArmoredString(clearSignedContent);

            // Assert
            Assert.True(result.IsVerified);
            Assert.Equal(testFactory.Content, result.ClearText.TrimEnd());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void ClearSignAndDoNotVerifyArmoredString_CreateClearSignedStringAndDoNotVerifyAndRead(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string clearSignedContent = pgpEncrypt.ClearSignArmoredString(testFactory.Content);
            VerificationResult result = pgpDecrypt.VerifyAndReadClearArmoredString(clearSignedContent);

            // Assert
            Assert.False(result.IsVerified);
            Assert.Equal(testFactory.Content, result.ClearText.TrimEnd());

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptArmoredString_CreateEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);

            
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptArmoredStringAndSign_CreateEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedAndSignedContent = pgp.EncryptArmoredStringAfterSign(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptArmoredStringAndSign_CreateEncryptedAndSignedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated);
            
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedAndSignedContent = pgp.EncryptArmoredStringAfterSign(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredString(encryptedContent, out _);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public void DecryptArmoredString_DecryptEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                HashAlgorithm = hashAlgorithmTag
            };

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredString(encryptedContent, out _);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.EncryptArmoredString(testFactory.Content);
            string decryptedContent1 = pgpEncrypt.DecryptArmoredString(encryptedContent, out _);
            string decryptedContent2 = pgpDecrypt.DecryptArmoredString(encryptedContent, out _);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent1);
            Assert.NotNull(decryptedContent2);
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAfterSign(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredString(encryptedContent, out _);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredString_DecryptSignedAndEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedAndSignedContent = pgpEncrypt.EncryptArmoredStringAfterSign(testFactory.Content);
            string decryptedContent1 = pgpEncrypt.DecryptArmoredString(encryptedAndSignedContent, out _);
            string decryptedContent2 = pgpDecrypt.DecryptArmoredString(encryptedAndSignedContent, out _);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);
            Assert.NotNull(decryptedContent1);
            Assert.NotNull(decryptedContent2);
            Assert.Equal(testFactory.Content, decryptedContent1.Trim());
            Assert.Equal(testFactory.Content, decryptedContent2.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptUnsignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string decryptedContent = null;
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            var ex = Assert.Throws<PgpException>( () => decryptedContent = pgp.DecryptArmoredStringAndVerify(encryptedContent, out _));

            // Assert
            Assert.Equal("File was not signed.", ex.Message);
            Assert.NotNull(encryptedContent);
            Assert.Null(decryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            TestFactory testFactory3 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            testFactory3.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory3.PublicKey, testFactory.PrivateKey, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string decryptedContent = null;
            string encryptedContent = pgpEncrypt.EncryptArmoredStringAfterSign(testFactory.Content);
            var ex = Assert.Throws<PgpException>( () => decryptedContent = pgpDecrypt.DecryptArmoredStringAndVerify(encryptedContent, out _));

            // Assert
            Assert.Equal("Secret key for message not found.", ex.Message);
            Assert.NotNull(encryptedContent);
            Assert.Null(decryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAfterSign(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredStringAndVerify(encryptedContent, out _);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptSignedAndEncryptedAndCompressedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAfterSign(testFactory.Content);
            string decryptedContent = pgp.DecryptArmoredStringAndVerify(encryptedContent, out _);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void DecryptArmoredStringAndVerify_DecryptSignedAndEncryptedStringDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.EncryptArmoredStringAfterSign(testFactory.Content);
            string decryptedContent = pgpDecrypt.DecryptArmoredStringAndVerify(encryptedContent, out _);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredStringAfterSign(testFactory.Content);
            bool verified = pgp.VerifyArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.EncryptArmoredStringAfterSign(testFactory.Content);
            bool verified = pgpDecrypt.VerifyArmoredString(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_VerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = pgp.SignArmoredString(testFactory.Content);
            bool verified = pgp.VerifyArmoredString(signedContent);

            // Assert
            Assert.NotNull(signedContent);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyAndRead_VerifySignedStringAndReturnContents(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = pgp.SignArmoredString(testFactory.Content);
            VerificationResult verificationResult = pgp.VerifyAndReadSignedArmoredString(signedContent);

            // Assert
            Assert.NotNull(signedContent);
            Assert.True(verificationResult.IsVerified);
            Assert.Equal(testFactory.Content, verificationResult.ClearText.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Verify_DoNotVerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string signedContent = pgpEncrypt.SignArmoredString(testFactory.Content);
            bool verified = pgpDecrypt.VerifyArmoredString(signedContent);

            // Assert
            Assert.NotNull(signedContent);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyAndRead_DoNotVerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string signedContent = pgpEncrypt.SignArmoredString(testFactory.Content);
            VerificationResult verificationResult = pgpDecrypt.VerifyAndReadSignedArmoredString(signedContent);

            // Assert
            Assert.NotNull(signedContent);
            Assert.False(verificationResult.IsVerified);
            Assert.Equal(string.Empty, verificationResult.ClearText.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStringRecipient(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            PgpPublicKey pgpPublicKey = Utilities.ReadPublicKey(testFactory.PublicKey);
            IEnumerable<long> recipients = pgp.GetArmoredStringRecipients(encryptedContent);

            // Assert
            Assert.Equal(pgpPublicKey.KeyId, recipients.FirstOrDefault());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Recipients_GetStringRecipients(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(KeyType.Generated, FileType.Known);

            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = pgp.EncryptArmoredString(testFactory.Content);
            List<PgpPublicKey> pgpPublicKeys = keys.Select(x => Utilities.ReadPublicKey(x)).ToList();
            IEnumerable<long> recipients = pgp.GetArmoredStringRecipients(encryptedContent);

            // Assert
            Assert.All(recipients, recipient => Assert.Contains(pgpPublicKeys, x => recipient == x.KeyId));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void VerifyAndReadSignedArmoredString_WhenEncryptedAndNotSigned_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.EncryptStream(inputFileStream, outputFileStream);
            
            // Act and Assert
            try
            {
                pgp.VerifyAndReadSignedArmoredString(testFactory.EncryptedContent, true);
                Assert.Fail("Expected exception not thrown");
            }
            catch (ArgumentException e)
            {
                Assert.Equal("Input is encrypted. Decrypt the input first.", e.Message);
            }
            finally
            {
                // Teardown
                testFactory.Teardown();
            }
        }
        #endregion Armor

        #region Inspect
        [Fact]
        public void Inspect_InspectEncryptedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            pgp.CompressionAlgorithm = CompressionAlgorithmTag.Uncompressed;

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.Encrypt(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.EncryptedContentFileInfo.OpenRead())
            {
                result = pgp.Inspect(inputFileStream);
            }

            // Assert
            using (new AssertionScope())
            {
                result.IsArmored.Should().BeTrue();
                result.IsCompressed.Should().BeFalse();
                result.IsEncrypted.Should().BeTrue();
                result.IsIntegrityProtected.Should().BeTrue();
                result.IsSigned.Should().BeFalse();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Inspect_InspectCompressedEncryptedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgp.Encrypt(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.EncryptedContentFileInfo.OpenRead())
            {
                result = pgp.Inspect(inputFileStream);
            }

            // Assert
            using (new AssertionScope())
            {
                result.IsArmored.Should().BeTrue();
                result.IsCompressed.Should().BeTrue();
                result.IsEncrypted.Should().BeTrue();
                result.IsIntegrityProtected.Should().BeTrue();
                result.IsSigned.Should().BeFalse();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Inspect_InspectSignedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                pgp.Sign(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = pgp.Inspect(inputFileStream);
            }

            // Assert
            using (new AssertionScope())
            {
                result.IsArmored.Should().BeTrue();
                result.IsCompressed.Should().BeFalse();
                result.IsEncrypted.Should().BeFalse();
                result.IsIntegrityProtected.Should().BeFalse();
                result.IsSigned.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Inspect_InspectCompressedSignedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                pgp.Sign(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = pgp.Inspect(inputFileStream);
            }

            // Assert
            using (new AssertionScope())
            {
                result.IsArmored.Should().BeTrue();
                result.IsCompressed.Should().BeTrue();
                result.IsEncrypted.Should().BeFalse();
                result.IsIntegrityProtected.Should().BeFalse();
                result.IsSigned.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Inspect_InspectCompressedSignedEncryptedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                pgp.EncryptAfterSign(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = pgp.Inspect(inputFileStream);
            }

            // Assert
            using (new AssertionScope())
            {
                result.IsArmored.Should().BeTrue();
                result.IsCompressed.Should().BeTrue();
                result.IsEncrypted.Should().BeTrue();
                result.IsIntegrityProtected.Should().BeTrue();
                result.IsSigned.Should().BeTrue();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Fact]
        public void Inspect_InspectEncryptedHeaders()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            pgp.CompressionAlgorithm = CompressionAlgorithmTag.Uncompressed;

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                pgp.Encrypt(inputFileStream, outputFileStream, headers: new Dictionary<string, string>() { { "Comment", "Test comment" } });

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = pgp.Inspect(inputFileStream);
            }

            // Assert
            using (new AssertionScope())
            {
                result.IsArmored.Should().BeTrue();
                result.IsCompressed.Should().BeFalse();
                result.IsEncrypted.Should().BeTrue();
                result.IsIntegrityProtected.Should().BeTrue();
                result.IsSigned.Should().BeFalse();
            }

            using (new AssertionScope())
            {
                result.MessageHeaders.Should().HaveCount(2);
                result.MessageHeaders.Should().ContainKey("Comment");
                result.MessageHeaders["Comment"].Should().Be("Test comment");
                result.Comment.Should().Be("Test comment");
                result.MessageHeaders.Should().ContainKey("Version");
                result.MessageHeaders["Version"].Should().StartWith("BouncyCastle.NET Cryptography ");
                result.Version.Should().StartWith("BouncyCastle.NET Cryptography ");
            }

            // Teardown
            testFactory.Teardown();
        }

        #endregion Inspect

        public static IEnumerable<object[]> KeyTypeValues()
        {
            foreach (var keyType in Enum.GetValues(typeof(KeyType)))
            {
                yield return new object[] { keyType };
            }
        }

        public static IEnumerable<object[]> HashAlgorithmTagValues()
        {
            foreach (var hashAlgorithmTag in Enum.GetValues(typeof(HashAlgorithmTag)))
            {
                yield return new object[] { hashAlgorithmTag };
            }
        }
    }
}
