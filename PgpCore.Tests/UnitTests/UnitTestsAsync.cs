using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FluentAssertions;
using FluentAssertions.Execution;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCoreM.Models;
using Xunit;

namespace PgpCoreM.Tests
{
    public class UnitTestsAsync
    {
        private static class File
        {
            public static FileStream Create(string path) => System.IO.File.Create(path);
            public static bool Exists(string path) => System.IO.File.Exists(path);
#if NETFRAMEWORK
            public static Task<string> ReadAllTextAsync(string path) => Task.FromResult(System.IO.File.ReadAllText(path));
            public static Task<string> ReadAllTextAsync(FileInfo file) => Task.FromResult(System.IO.File.ReadAllText(file.FullName));
            public static Task WriteAllLinesAsync(string path, string[] lines) => Task.Run(() => System.IO.File.WriteAllLines(path, lines));
#else
            public static Task<string> ReadAllTextAsync(string path) => System.IO.File.ReadAllTextAsync(path);
            public static Task<string> ReadAllTextAsync(FileInfo file) => System.IO.File.ReadAllTextAsync(file.FullName);
            public static Task WriteAllLinesAsync(string path, string[] lines) => Task.FromResult(System.IO.File.WriteAllLinesAsync(path, lines));
#endif
            public static Task<string[]> ReadAllLinesAsync(string path) => Task.FromResult(System.IO.File.ReadAllLines(path));
        }

        #region File - FileInfo
        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptFileAsync_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptFileAsync_CreateEncryptedFileWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, headers:headers);
            string encryptedContent = await File.ReadAllTextAsync(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Comment: Test comment", encryptedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptFileAsync_CreateEncryptedFileWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, headers: headers);
            string encryptedContent = await File.ReadAllTextAsync(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Version: Test version", encryptedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task EncryptFileAsync_CreateEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgp = new PGP(encryptionKeys);
            pgp.HashAlgorithm = hashAlgorithmTag;

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignFileAsync_CreateSignedFileWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            await pgp.SignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo, headers: headers);
            string signedContent = await File.ReadAllTextAsync(testFactory.SignedContentFileInfo);

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
        public async Task SignFileAsync_CreateSignedFileWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            await pgp.SignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo, headers: headers);
            string signedContent = await File.ReadAllTextAsync(testFactory.SignedContentFileInfo);

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
        public async Task SignFileAsync_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.SignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignFileAsync_CreateClearSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.ClearSignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndVerifyFileAsync_CreateClearSignedFileAndVerifyWithPublicKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            await pgpEncrypt.ClearSignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(await pgpVerify.VerifyClearFileAsync(testFactory.SignedContentFileInfo));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndVerifyFileAsync_CreateClearSignedFileAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.ClearSignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(await pgp.VerifyClearFileAsync(testFactory.SignedContentFileInfo));

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndDoNotVerifyFileAsync_CreateClearSignedFileAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);
            EncryptionKeys encryptionKeysSign = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys encryptionKeysVerify = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(encryptionKeysSign);
            PGP pgpVerify = new PGP(encryptionKeysVerify);

            // Act
            await pgpSign.ClearSignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);

            // Assert
            Assert.False(await pgpVerify.VerifyClearFileAsync(testFactory.SignedContentFileInfo));

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptFileAsync_CreateEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

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
        public async Task EncryptFileAndSignAsync_CreateEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptFileAndSignAsync_CreateEncryptedAndSignedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            List<FileInfo> keys = new List<FileInfo>()
            {
                testFactory.PublicKeyFileInfo,
                testFactory2.PublicKeyFileInfo
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);

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
        public async Task DecryptFileAsync_DecryptEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptFileAsync_DecryptEncryptedCompressedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task DecryptFileAsync_DecryptEncryptedFileWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            pgpEncrypt.HashAlgorithm = hashAlgorithmTag;

            // Act
            await pgpEncrypt.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        ////[Theory]
        ////[InlineData(KeyType.Generated, FileType.GeneratedLarge)]
        ////public async Task DecryptLargeFile_DecryptEncryptedFile(KeyType keyType, FileType fileType)
        ////{
        ////    // Arrange
        ////    Arrange(keyType, fileType);
        ////    PGP pgp = new PGP(encryptionKeys);

        ////    // Act
        ////    pgp.EncryptFile(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, testFactory.PublicKeyFilePath);
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
        public async Task DecryptFileAsync_DecryptEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
            await pgpEncrypt.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpEncrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo);

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
        public async Task DecryptFileAsync_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo, armor: false);
            await pgp.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptFileAsync_DecryptSignedAndEncryptedFileWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
            await pgpEncrypt.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpEncrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAsync(testFactory.EncryptedContentFileInfo, testFactory2.DecryptedContentFileInfo);

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
        public async Task DecryptFileAndVerifyAsync_DecryptUnsignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => await pgpDecrypt.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFileInfo,
                testFactory.DecryptedContentFileInfo));

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
        public async Task DecryptFileAndVerifyAsync_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => await pgpDecrypt.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFileInfo,
                testFactory.DecryptedContentFileInfo));

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
        public async Task DecryptFileAndVerifyAsync_DecryptSignedAndEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptFileAndVerifyAsync_DecryptSignedAndEncryptedAndCompressedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);

            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgp.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task DecryptFileAndVerifyAsync_DecryptSignedAndEncryptedFileDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory2.PrivateKeyFileInfo, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            await pgpDecrypt.DecryptFileAndVerifyAsync(testFactory.EncryptedContentFileInfo, testFactory.DecryptedContentFileInfo);

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
        public async Task VerifyFileAsync_VerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            bool verified = await pgp.VerifyFileAsync(testFactory.EncryptedContentFileInfo);

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
        public async Task VerifyFileAsync_DoNotVerifyEncryptedAndSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.EncryptFileAndSignAsync(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            bool verified = await pgpDecrypt.VerifyFileAsync(testFactory.EncryptedContentFileInfo);

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
        public async Task VerifyAsync_VerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.SignAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = await pgp.VerifyAsync(testFactory.SignedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.True(verified);
            
            using (StreamReader streamReader = testFactory.DecryptedContentFileInfo.OpenText())
            {
                string decryptedContent = await streamReader.ReadToEndAsync();
                testFactory.Content.Should().BeEquivalentTo(decryptedContent);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyFileAsync_DoNotVerifySignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            await pgpEncrypt.SignFileAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = await pgpDecrypt.VerifyFileAsync(testFactory.SignedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }
        
        [Fact]
        public async Task VerifyFileAsync_ThrowIfEncrypted()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.GeneratedMedium);
            
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream);
            
            // Act and Assert
            try
            {
                await pgp.VerifyFileAsync(testFactory.EncryptedContentFileInfo, true);
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

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyAsync_VerifyAndReadSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            await pgp.SignAsync(testFactory.ContentFileInfo, testFactory.SignedContentFileInfo);
            bool verified = await pgp.VerifyAsync(testFactory.SignedContentFileInfo, testFactory.DecryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }
        #endregion File - FileInfo

        #region Stream
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptStreamAsync_CreateEncryptedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptStreamAsync_CreateEncryptedFileWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, headers: headers);

            string encryptedContent = await File.ReadAllTextAsync(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.Contains("Comment: Test comment", encryptedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptStreamAsync_CreateEncryptedFileWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream, headers: headers);

            string encryptedContent = await File.ReadAllTextAsync(testFactory.EncryptedContentFileInfo);

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
        public async Task SignStreamAsync_CreateSignedFile(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.SignStreamAsync(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignStreamAsync_CreateSignedStreamWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, headers: headers);

            string signedContent = await File.ReadAllTextAsync(testFactory.EncryptedContentFileInfo);

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
        public async Task SignStreamAsync_CreateSignedStreamWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.SignStreamAsync(inputFileStream, outputFileStream, headers: headers);

            string signedContent = await File.ReadAllTextAsync(testFactory.EncryptedContentFileInfo);

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
        public async Task ClearSignStreamAsync_CreateClearSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgp.ClearSignStreamAsync(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignStreamAsync_CreateClearSignedStreamAndVerifyWithPublicKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpVerify = new PGP(verificationKeys);
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgpEncrypt.ClearSignStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
            using (Stream publicKeyStream = testFactory.PublicKeyStream)
                verified = await pgpVerify.VerifyClearStreamAsync(inputFileStream);

            // Assert
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignStreamAsync_CreateClearSignedStreamAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo, testFactory.PrivateKeyFileInfo, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgp.ClearSignStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = await pgp.VerifyClearStreamAsync(inputFileStream);

            // Assert
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignStreamAsync_CreateClearSignedStreamAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);
            EncryptionKeys encryptionKeysSign = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys encryptionKeysVerify = new EncryptionKeys(testFactory2.PublicKeyFileInfo);
            PGP pgpSign = new PGP(encryptionKeysSign);
            PGP pgpVerify = new PGP(encryptionKeysVerify);
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgpSign.ClearSignStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = await pgpVerify.VerifyClearStreamAsync(inputFileStream);

            // Assert
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignStreamAsync_CreateClearSignedStreamWithBadContentAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKeyFileInfo, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpVerify = new PGP(verificationKeys);
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgpEncrypt.ClearSignStreamAsync(inputFileStream, outputFileStream);

            string fileContent = await File.ReadAllTextAsync(testFactory.SignedContentFileInfo.FullName);
            fileContent = fileContent.Replace("fox", "rabbit");
            System.IO.File.WriteAllText(testFactory.SignedContentFileInfo.FullName, fileContent);

            using (Stream inputFileStream = testFactory.SignedContentStream)
            using (Stream publicKeyFileStream = testFactory.PublicKeyStream)
                verified = await pgpVerify.VerifyClearStreamAsync(inputFileStream);

            // Assert
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptStreamAsync_CreateEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptStreamAndSignAsync_CreateEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptStreamAndSignAsync_CreateEncryptedAndSignedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptStreamAsync_DecryptEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpEncrypt.EncryptStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                await pgpDecrypt.DecryptStreamAsync(inputFileStream, outputFileStream);

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
        public async Task DecryptStreamAsync_DecryptEncryptedCompressedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpEncrypt.EncryptStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                await pgpDecrypt.DecryptStreamAsync(inputFileStream, outputFileStream);

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
        public async Task DecryptStreamAsync_DecryptEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
                await pgpEncrypt.EncryptStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                await pgpEncrypt.DecryptStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory2.DecryptedContentFileInfo.Create())
                await pgpDecrypt.DecryptStreamAsync(inputFileStream, outputFileStream);

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
        public async Task DecryptStreamAsync_DecryptSignedAndEncryptedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                await pgp.DecryptStreamAsync(inputFileStream, outputFileStream);

            bool verified = pgp.VerifyFile(testFactory.EncryptedContentFileInfo);

            // Assert
            Assert.True(testFactory.EncryptedContentFileInfo.Exists);
            Assert.True(testFactory.DecryptedContentFileInfo.Exists);
            Assert.Equal(testFactory.Content, testFactory.DecryptedContent.Trim());
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptStreamAsync_DecryptSignedAndEncryptedStreamWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
                await pgpEncrypt.EncryptStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory.DecryptedContentFileInfo.Create())
                await pgpEncrypt.DecryptStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
            using (Stream outputFileStream = testFactory2.DecryptedContentFileInfo.Create())
                await pgpDecrypt.DecryptStreamAsync(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = await pgpEncrypt.VerifyStreamAsync(inputFileStream);

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
        public async Task VerifyAsync_VerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAndSignAsync(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = await pgp.VerifyStreamAsync(inputFileStream);

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
        public async Task VerifyAsync_DoNotVerifyEncryptedAndSignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyStream);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpEncrypt.EncryptStreamAndSignAsync(inputFileStream, outputFileStream);

            bool verified = false;

            using (Stream inputFileStream = testFactory.EncryptedContentStream)
                verified = await pgpDecrypt.VerifyStreamAsync(inputFileStream);

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
        public async Task VerifyAsync_VerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            bool verified = false;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgp.SignStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = await pgp.VerifyStreamAsync(inputFileStream);

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
        public async Task VerifyAsync_DoNotVerifySignedStream(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKeyStream, testFactory2.PrivateKeyStream, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);
            bool verified = true;

            // Act
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgpEncrypt.SignStreamAsync(inputFileStream, outputFileStream);

            using (Stream inputFileStream = testFactory.SignedContentStream)
                verified = await pgpDecrypt.VerifyStreamAsync(inputFileStream);

            // Assert
            Assert.True(testFactory.SignedContentFileInfo.Exists);
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
        }
        
        [Fact]
        public async Task VerifyStreamAsync_ThrowIfEncrypted()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.GeneratedMedium);
            
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream);
            
            // Act and Assert
            try
            {
                await pgp.VerifyStreamAsync(testFactory.EncryptedContentStream, true);
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
        public async Task EncryptArmoredStringAsync_CreateEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptArmoredStringAsync_CreateEncryptedStringWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, headers: headers);

            // Assert
            Assert.Contains("Comment: Test comment", encryptedContent);
            Assert.Contains("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(KeyTypeValues))]
        public async Task EncryptArmoredStringAsync_CreateEncryptedStringWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content, headers: headers);

            // Assert
            Assert.Contains("Version: Test version", encryptedContent);
            Assert.DoesNotContain("Version: BouncyCastle.NET Cryptography ", encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task EncryptArmoredStringAsync_CreateEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgp = new PGP(encryptionKeys);
            pgp.HashAlgorithm = hashAlgorithmTag;

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignArmoredStringAsync_CreateSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = await pgp.SignArmoredStringAsync(testFactory.Content);

            // Assert
            Assert.NotNull(signedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignArmoredStringAsync_CreateSignedStringWithCommentHeader_ShouldAddCommentHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Comment", "Test comment" }
            };

            // Act
            string signedContent = await pgp.SignArmoredStringAsync(testFactory.Content, headers: headers);

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
        public async Task SignArmoredStringAsync_CreateSignedStringWithVersionHeader_ShouldOverwriteDefaultHeader(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Version", "Test version" }
            };

            // Act
            string signedContent = await pgp.SignArmoredStringAsync(testFactory.Content, headers: headers);
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
        public async Task ClearSignArmoredStringAsync_CreateClearSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = await pgp.ClearSignArmoredStringAsync(testFactory.Content);

            // Assert
            Assert.NotNull(clearSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndVerifyArmoredStringAsync_CreateClearSignedStringAndVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = await pgp.ClearSignArmoredStringAsync(testFactory.Content);
            bool verified = await pgp.VerifyClearArmoredStringAsync(clearSignedContent);

            // Assert
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndDoNotVerifyArmoredStringAsync_CreateClearSignedStringAndDoNotVerify(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string clearSignedContent = await pgpEncrypt.ClearSignArmoredStringAsync(testFactory.Content);
            bool verified = await pgpDecrypt.VerifyClearArmoredStringAsync(clearSignedContent);

            // Assert
            Assert.False(verified);

            // Teardown
            testFactory.Teardown();
            testFactory2.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAndVerifyArmoredStringAsync_CreateClearSignedStringAndVerifyAndRead(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string clearSignedContent = await pgp.ClearSignArmoredStringAsync(testFactory.Content);
            VerificationResult result = await pgp.VerifyAndReadClearArmoredStringAsync(clearSignedContent);

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
        public async Task ClearSignAndDoNotVerifyArmoredStringAsync_CreateClearSignedStringAndDoNotVerifyAndRead(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string clearSignedContent = await pgpEncrypt.ClearSignArmoredStringAsync(testFactory.Content);
            VerificationResult result = await pgpDecrypt.VerifyAndReadClearArmoredStringAsync(clearSignedContent);

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
        public async Task EncryptArmoredStringAsync_CreateEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);

            
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content);

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
        public async Task EncryptArmoredStringAndSignAsync_CreateEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedAndSignedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content);

            // Assert
            Assert.NotNull(encryptedAndSignedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptArmoredStringAndSignAsync_CreateEncryptedAndSignedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated);
            
            List<string> keys = new List<string>()
            {
                testFactory.PublicKey,
                testFactory2.PublicKey
            };

            EncryptionKeys encryptionKeys = new EncryptionKeys(keys, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedAndSignedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content);

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
        public async Task DecryptArmoredStringAsync_DecryptEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptArmoredStringAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptArmoredStringAsync(encryptedContent);

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
        public async Task DecryptArmoredStringAsync_DecryptCompressedEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            PGP pgpEncrypt = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptArmoredStringAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptArmoredStringAsync(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.NotNull(decryptedContent);
            Assert.Equal(testFactory.Content, decryptedContent.Trim());

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [MemberData(nameof(HashAlgorithmTagValues))]
        public async Task DecryptArmoredStringAsync_DecryptEncryptedStringWithDifferentHashAlgorithms(HashAlgorithmTag hashAlgorithmTag)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Known, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                HashAlgorithm = hashAlgorithmTag
            };

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content);
            string decryptedContent = await pgp.DecryptArmoredStringAsync(encryptedContent);

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
        public async Task DecryptArmoredStringAsync_DecryptEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
            string encryptedContent = await pgpEncrypt.EncryptArmoredStringAsync(testFactory.Content);
            string decryptedContent1 = await pgpEncrypt.DecryptArmoredStringAsync(encryptedContent);
            string decryptedContent2 = await pgpDecrypt.DecryptArmoredStringAsync(encryptedContent);

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
        public async Task DecryptArmoredStringAsync_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content);
            string decryptedContent = await pgp.DecryptArmoredStringAsync(encryptedContent);

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
        public async Task DecryptArmoredStringAsync_DecryptSignedAndEncryptedStringWithMultipleKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);

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
            string encryptedAndSignedContent = await pgpEncrypt.EncryptArmoredStringAndSignAsync(testFactory.Content);
            string decryptedContent1 = await pgpEncrypt.DecryptArmoredStringAsync(encryptedAndSignedContent);
            string decryptedContent2 = await pgpDecrypt.DecryptArmoredStringAsync(encryptedAndSignedContent);

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptUnsignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string decryptedContent = null;
            string encryptedContent = await pgp.EncryptArmoredStringAsync(testFactory.Content);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent));

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptWithWrongKey(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory.PrivateKey, testFactory.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string decryptedContent = null;
            string encryptedContent = await pgpEncrypt.EncryptArmoredStringAndSignAsync(testFactory.Content);
            var ex = await Assert.ThrowsAsync<PgpException>(async () => decryptedContent = await pgpDecrypt.DecryptArmoredStringAndVerifyAsync(encryptedContent));

            // Assert
            Assert.Equal("Failed to verify file.", ex.Message);
            Assert.NotNull(encryptedContent);
            Assert.Null(decryptedContent);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptSignedAndEncryptedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content);
            string decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent);

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptSignedAndEncryptedAndCompressedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip,
            };

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content);
            string decryptedContent = await pgp.DecryptArmoredStringAndVerifyAsync(encryptedContent);

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
        public async Task DecryptArmoredStringAndVerifyAsync_DecryptSignedAndEncryptedStringDifferentKeys(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptArmoredStringAndSignAsync(testFactory.Content);
            string decryptedContent = await pgpDecrypt.DecryptArmoredStringAndVerifyAsync(encryptedContent);

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
        public async Task VerifyAsync_VerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string encryptedContent = await pgp.EncryptArmoredStringAndSignAsync(testFactory.Content);
            bool verified = await pgp.VerifyArmoredStringAsync(encryptedContent);

            // Assert
            Assert.NotNull(encryptedContent);
            Assert.True(verified);

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task VerifyAsync_DoNotVerifyEncryptedAndSignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey, testFactory2.PrivateKey, testFactory2.Password);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptArmoredStringAndSignAsync(testFactory.Content);
            bool verified = await pgpDecrypt.VerifyArmoredStringAsync(encryptedContent);

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
        public async Task VerifyAsync_VerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = await pgp.SignArmoredStringAsync(testFactory.Content);
            bool verified = await pgp.VerifyArmoredStringAsync(signedContent);

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
        public async Task VerifyAsync_VerifySignedStringAndReturnContents(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            // Act
            string signedContent = await pgp.SignAsync(testFactory.Content);
            bool verified = await pgp.VerifyAsync(signedContent);

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
        public async Task VerifyAsync_DoNotVerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string signedContent = await pgpEncrypt.SignArmoredStringAsync(testFactory.Content);
            bool verified = await pgpDecrypt.VerifyArmoredStringAsync(signedContent);

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
        public async Task VerifyAndReadAsync_DoNotVerifySignedString(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            await testFactory2.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys decryptionKeys = new EncryptionKeys(testFactory2.PublicKey);

            PGP pgpEncrypt = new PGP(encryptionKeys);
            PGP pgpDecrypt = new PGP(decryptionKeys);

            // Act
            string signedContent = await pgpEncrypt.SignArmoredStringAsync(testFactory.Content);
            VerificationResult verificationResult = await pgpDecrypt.VerifyAndReadSignedArmoredStringAsync(signedContent);

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
        public async Task VerifyAndReadSignedArmoredStringAsync_WhenEncryptedAndNotSigned_ShouldThrowException(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);
            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptStreamAsync(inputFileStream, outputFileStream);

            // Act and Assert
            try
            {
                await pgp.VerifyAndReadSignedArmoredStringAsync(testFactory.EncryptedContent, true);
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
        public async Task InspectAsync_InspectEncryptedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptAsync(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.EncryptedContentFileInfo.OpenRead())
            {
                result = await pgp.InspectAsync(inputFileStream);
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
        public async Task InspectAsync_InspectCompressedEncryptedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgp.EncryptAsync(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.EncryptedContentFileInfo.OpenRead())
            {
                result = await pgp.InspectAsync(inputFileStream);
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
        public async Task InspectAsync_InspectSignedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgp.SignAsync(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = await pgp.InspectAsync(inputFileStream);
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
        public async Task InspectAsync_InspectCompressedSignedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgp.SignAsync(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = await pgp.InspectAsync(inputFileStream);
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
        public async Task InspectAsync_InspectCompressedSignedEncryptedStream()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys)
            {
                CompressionAlgorithm = CompressionAlgorithmTag.Zip
            };

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgp.EncryptAndSignAsync(inputFileStream, outputFileStream);

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = await pgp.InspectAsync(inputFileStream);
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
        public async Task InspectAsync_InspectEncryptedHeaders()
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            PGP pgp = new PGP(encryptionKeys);

            using (Stream inputFileStream = testFactory.ContentStream)
            using (Stream outputFileStream = testFactory.SignedContentFileInfo.Create())
                await pgp.EncryptAsync(inputFileStream, outputFileStream, headers: new Dictionary<string, string>() { { "Comment", "Test comment" } });

            // Act
            PgpInspectResult result = null;

            using (Stream inputFileStream = testFactory.SignedContentFileInfo.OpenRead())
            {
                result = await pgp.InspectAsync(inputFileStream);
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
