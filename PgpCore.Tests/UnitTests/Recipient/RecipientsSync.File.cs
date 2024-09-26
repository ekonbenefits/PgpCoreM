﻿using FluentAssertions.Execution;
using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Xunit.Abstractions;

namespace PgpCoreM.Tests.UnitTests.Recipient
{
    public class RecipientsSync : TestBase
    {

        private readonly ITestOutputHelper output;

        public RecipientsSync(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        public void GetRecipients_GetTheRecipientOfEncyptedMessage_ShouldReturnRecipientId(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyFileInfo);
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory.ContentFileInfo, testFactory.EncryptedContentFileInfo);
            IEnumerable<long> recipients = pgpEncrypt.GetRecipients(testFactory.EncryptedContentFileInfo);
            output.WriteLine(testFactory.PublicKeyFileInfo.FullName);
            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                recipients.Should().NotBeEmpty();
                if (keyType == KeyType.Known)
                {
                    recipients.Should().HaveCount(3);
                }
                else
                {
                    recipients.Should().HaveCount(1);
                }

                using (Stream publicKeyStream = testFactory.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = ReadBestEncryptionPublicKey(publicKeyStream);
                    recipients.Any(it=>it == publicKey.KeyId).Should().BeTrue();
                }
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        public void GetRecipients_GetTheRecipientsOfEncyptedMessage_ShouldReturnRecipientIds(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory1 = new TestFactory();
            TestFactory testFactory2 = new TestFactory();
            testFactory1.Arrange(keyType, FileType.Known);
            testFactory2.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(new List<FileInfo>() { testFactory1.PublicKeyFileInfo, testFactory2.PublicKeyFileInfo });
            PGP pgpEncrypt = new PGP(encryptionKeys);

            // Act
            pgpEncrypt.Encrypt(testFactory1.ContentFileInfo, testFactory1.EncryptedContentFileInfo);
            IEnumerable<long> recipients = pgpEncrypt.GetRecipients(testFactory1.EncryptedContentFileInfo);

            // Assert
            using (new AssertionScope())
            {
                testFactory1.EncryptedContentFileInfo.Exists.Should().BeTrue();
                recipients.Should().NotBeEmpty();
                recipients.Should().HaveCount(2);

                using (Stream publicKeyStream = testFactory1.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = ReadBestEncryptionPublicKey(publicKeyStream);
                    recipients.Should().Contain(publicKey.KeyId);
                }

                using (Stream publicKeyStream = testFactory2.PublicKeyFileInfo.OpenRead())
                {
                    PgpPublicKey publicKey = ReadBestEncryptionPublicKey(publicKeyStream);
                    recipients.Should().Contain(publicKey.KeyId);
                }
            }

            // Teardown
            testFactory1.Teardown();
            testFactory2.Teardown();
        }
    }
}
