﻿using FluentAssertions.Execution;
using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using System.IO;
using PgpCoreM.Models;

namespace PgpCoreM.Tests.UnitTests.Sign
{
    public class SignAsync_String : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignAsync_SignMessageWithDefaultProperties_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.SignAsync(testFactory.Content);
            bool verified = await pgpVerify.VerifyAsync(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(signedContent);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(DEFAULTNAME);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignAsync_SignMessageWithName_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.SignAsync(testFactory.Content, name: TESTNAME);
            bool verified = await pgpVerify.VerifyAsync(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(signedContent);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(TESTNAME);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignAsync_SignMessageWithHeaders_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.SignAsync(testFactory.Content, headers: new Dictionary<string, string> { { TESTHEADERKEY, TESTHEADERVALUE } });
            bool verified = await pgpVerify.VerifyAsync(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(signedContent);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(DEFAULTNAME);
                pgpInspectResult.MessageHeaders.Should().HaveCount(2);
                pgpInspectResult.MessageHeaders.First().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.First().Value.Should().Be(VERSION);
                pgpInspectResult.MessageHeaders.Last().Key.Should().Be(TESTHEADERKEY);
                pgpInspectResult.MessageHeaders.Last().Value.Should().Be(TESTHEADERVALUE);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignAsync_SignMessageWithOldFormat_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.SignAsync(testFactory.Content, oldFormat: true);
            bool verified = await pgpVerify.VerifyAsync(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(signedContent);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(DEFAULTNAME);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(VERSION);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAsync_SignMessageWithDefaultProperties_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.ClearSignAsync(testFactory.Content);
            bool verified = await pgpVerify.VerifyClearAsync(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                signedContent.Should().Contain(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAsync_SignMessageWithHeaders_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            PGP pgpSign = new PGP(signingKeys);
            PGP pgpVerify = new PGP(verificationKeys);

            // Act
            string signedContent = await pgpSign.ClearSignAsync(testFactory.Content, headers: new Dictionary<string, string> { { TESTHEADERKEY, TESTHEADERVALUE } });
            bool verified = await pgpVerify.VerifyClearAsync(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                signedContent.Should().Contain(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }
    }
}
