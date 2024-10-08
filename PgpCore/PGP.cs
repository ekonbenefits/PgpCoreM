using System.Linq;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using PgpCoreM.Extensions;
using PgpCoreM.Helpers;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PgpCoreM.Abstractions;
using PgpCoreM;
using PgpCoreM.Models;

namespace PgpCoreM
{
    public partial class PGP : IPGP
	{
		public static PGP Instance => _instance ??= new PGP();
		private static PGP _instance;

        private static SecureRandom _secRandom;
        public static SecureRandom SecRandom => _secRandom ??= new SecureRandom();

		private const int BufferSize = 0x10000;
		private const string DefaultFileName = "name";

        public static readonly List<CompressionAlgorithmTag> DefaultCompressionAlgs =
        [
			CompressionAlgorithmTag.ZLib,
			CompressionAlgorithmTag.BZip2,
            CompressionAlgorithmTag.Zip,
            CompressionAlgorithmTag.Uncompressed,
        ];

        public static readonly List<HashAlgorithmTag> DefaultHashAlgs =
        [
            HashAlgorithmTag.Sha256,
			HashAlgorithmTag.Sha384,
            HashAlgorithmTag.Sha512
        ];

        public static readonly List<SymmetricKeyAlgorithmTag> DefaultSymmetricKeyAlgs =
        [
            SymmetricKeyAlgorithmTag.Aes128,
			SymmetricKeyAlgorithmTag.Aes192,
            SymmetricKeyAlgorithmTag.Aes256
        ];

        private CompressionAlgorithmTag[] _preferredCompressionAlgorithms;

        public CompressionAlgorithmTag[] PreferredCompressionAlgorithms
        {
            get
            {	if (_preferredCompressionAlgorithms is { Length: > 0 })
                {
                    return _preferredCompressionAlgorithms;
                }

                return PreferredAlgHelper().ToArray();

                IEnumerable<CompressionAlgorithmTag> PreferredAlgHelper()
                {
                   
                    yield return CompressionAlgorithm;
                 

                    foreach (var alg in DefaultCompressionAlgs
                                 .Where(it=> it != CompressionAlgorithm))
                    {
                        yield return alg;
                    }
                }
            }
            set => _preferredCompressionAlgorithms = value;
        }

        private HashAlgorithmTag[] _preferredHashAlgorithms;
    


        public HashAlgorithmTag[] PreferredHashAlgorithms
        {
            get
            {
                if (_preferredHashAlgorithms is { Length: > 0 })
                {
                    return _preferredHashAlgorithms;
                }

                return PreferredAlgHelper().ToArray();

                IEnumerable<HashAlgorithmTag> PreferredAlgHelper()
                {
                  
                    yield return HashAlgorithm;
                  

                    foreach (var alg in DefaultHashAlgs
                                 .Where(it => it != HashAlgorithm))
                    {
                        yield return alg;
                    }
                }
            }
            set => _preferredHashAlgorithms = value;
        }

        private SymmetricKeyAlgorithmTag[] _preferredSymmetricKeyAlgorithms;
        public SymmetricKeyAlgorithmTag[] PreferredSymmetricKeyAlgorithms
        {
            get
            {
                if (_preferredSymmetricKeyAlgorithms is { Length: > 0 })
                {
                    return _preferredSymmetricKeyAlgorithms;
                }

                return PreferredAlgHelper().ToArray();

                IEnumerable<SymmetricKeyAlgorithmTag> PreferredAlgHelper()
                {
                   
                    yield return SymmetricKeyAlgorithm;


                    foreach (var alg in DefaultSymmetricKeyAlgs
                                 .Where(it => it != SymmetricKeyAlgorithm))
                    {
                        yield return alg;
                    }
                }
            }
            set => _preferredSymmetricKeyAlgorithms = value;
        }	


        public CompressionAlgorithmTag CompressionAlgorithm { get; set; } = CompressionAlgorithmTag.Zip;

        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; } = SymmetricKeyAlgorithmTag.Aes128;


		public AsymmetricAlgorithm PublicKeyAlgorithm { get; set; } = AsymmetricAlgorithm.Rsa;

		public PGPFileType FileType { get; set; } = PGPFileType.Binary;

		public HashAlgorithmTag HashAlgorithm { get; set; } = HashAlgorithmTag.Sha256;

		public IKeySet EncryptionKeys { get; private set; }

        public int SecurityStrengthInBits { get; set; } = 128;

		#region Constructor

		public PGP()
		{ }

        public PGP(int securityStrengthInBits, AsymmetricAlgorithm alg = AsymmetricAlgorithm.Rsa)
        {
			SecurityStrengthInBits = securityStrengthInBits;
			PublicKeyAlgorithm = alg;
            SymmetricKeyAlgorithm = Utilities.GetSymmetricAlgorithm(securityStrengthInBits);

            if (alg == AsymmetricAlgorithm.Ec)
            {
                HashAlgorithm = securityStrengthInBits switch
                {
                    <= 128 => HashAlgorithmTag.Sha256,
                    <=192 => HashAlgorithmTag.Sha384,
                    <= 256 or  > 256 => HashAlgorithmTag.Sha512,
                };
            }


        }

        public PGP(IKeySet encryptionKeys)
		{
			EncryptionKeys = encryptionKeys;
		}

		#endregion Constructor

		#region Private helpers

		#region OutputEncryptedAsync

		private async Task OutputEncryptedAsync(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name, bool oldFormat)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
					{
						using (FileStream inputFileStream = inputFile.OpenRead())
						{
							await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream,
								signatureGenerator);
						}
					}
				}
			}
		}

		private async Task OutputEncryptedAsync(Stream inputStream, Stream outputStream, bool withIntegrityCheck,
			string name, bool oldFormat)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
					{
						await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
					}
				}
			}
		}

		#endregion OutputEncryptedAsync

		#region OutputEncrypted

		private void OutputEncrypted(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name, bool oldFormat)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
					{
						using (FileStream inputFileStream = inputFile.OpenRead())
						{
							WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
						}
					}
				}
			}
		}

		private void OutputEncrypted(Stream inputStream, Stream outputStream, bool withIntegrityCheck, string name, bool oldFormat)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
					{
						WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
					}
				}
			}
		}

		#endregion OutputEncrypted

		#region OutputSignedAsync

		private async Task OutputSignedAsync(FileInfo inputFile, Stream outputStream, string name, bool oldFormat)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
				{
					using (FileStream inputFileStream = inputFile.OpenRead())
					{
						await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator);
					}
				}
			}
		}

		private async Task OutputSignedAsync(Stream inputStream, Stream outputStream,
			string name, bool oldFormat)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
                {
                    await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
                }
            }
		}

		#endregion OutputSignedAsync

		#region OutputSigned

		private void OutputSigned(FileInfo inputFile, Stream outputStream, string name, bool oldFormat)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
				{
					using (FileStream inputFileStream = inputFile.OpenRead())
					{
						WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
					}
				}
			}
		}

		private void OutputSigned(Stream inputStream, Stream outputStream, string name, bool oldFormat)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
				{
					WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
				}
			}
		}

		#endregion OutputSigned

		#region OutputClearSignedAsync

		private async Task OutputClearSignedAsync(FileInfo inputFile, Stream outputStream, IDictionary<string, string> headers)
		{
			using (FileStream inputFileStream = inputFile.OpenRead())
			{
				await OutputClearSignedAsync(inputFileStream, outputStream, headers);
			}
		}

		private async Task OutputClearSignedAsync(Stream inputStream, Stream outputStream, IDictionary<string, string> headers)
		{
			using (StreamReader streamReader = new StreamReader(inputStream))
			using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
			{
				PgpSignatureGenerator pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

				while (streamReader.Peek() >= 0)
				{
					string line = await streamReader.ReadLineAsync();
					byte[] lineByteArray = Encoding.ASCII.GetBytes(line);
					// Does the line end with whitespace?
					// Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
					string cleanLine = line.TrimEnd();
					byte[] cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

					pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
					await armoredOutputStream.WriteAsync(lineByteArray, 0, lineByteArray.Length);

					// Add a line break back to the stream
					armoredOutputStream.Write((byte)'\r');
					armoredOutputStream.Write((byte)'\n');

					// Update signature with line breaks unless we're on the last line
					if (streamReader.Peek() >= 0)
					{
						pgpSignatureGenerator.Update((byte)'\r');
						pgpSignatureGenerator.Update((byte)'\n');
					}
				}

				armoredOutputStream.EndClearText();

				BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
				pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
			}
		}

		#endregion OutputClearSignedAsync

		#region OutputClearSigned

		private void OutputClearSigned(FileInfo inputFile, Stream outputStream, IDictionary<string, string> headers)
		{
			using (FileStream inputFileStream = inputFile.OpenRead())
			{
				OutputClearSigned(inputFileStream, outputStream, headers);
			}
		}

		private void OutputClearSigned(Stream inputStream, Stream outputStream, IDictionary<string, string> headers)
		{
            using (StreamReader streamReader = new StreamReader(inputStream))
			using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
			{
				PgpSignatureGenerator pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

				while (streamReader.Peek() >= 0)
				{
					string line = streamReader.ReadLine();
					if (line == null) continue;
					byte[] lineByteArray = Encoding.ASCII.GetBytes(line);
					// Does the line end with whitespace?
					// Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
					string cleanLine = line.TrimEnd();
					byte[] cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

					pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
					armoredOutputStream.Write(lineByteArray, 0, lineByteArray.Length);

					// Add a line break back to the stream
					armoredOutputStream.Write((byte)'\r');
					armoredOutputStream.Write((byte)'\n');

					// Update signature with line breaks unless we're on the last line
					if (streamReader.Peek() >= 0)
					{
						pgpSignatureGenerator.Update((byte)'\r');
						pgpSignatureGenerator.Update((byte)'\n');
					}
				}

				armoredOutputStream.EndClearText();

				BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
				pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
			}
		}

		#endregion OutputClearSigned

		#region WriteOutputAndSign

		private async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, FileStream inputFileStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = await inputFileStream.ReadAsync(buf, 0, buf.Length)) > 0)
			{
				await literalOut.WriteAsync(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFileStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = inputFileStream.Read(buf, 0, buf.Length)) > 0)
			{
				literalOut.Write(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		private async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, Stream inputStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = await inputStream.ReadAsync(buf, 0, buf.Length)) > 0)
			{
				await literalOut.WriteAsync(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, Stream inputStream,
			PgpSignatureGenerator signatureGenerator)
		{
			int length;
			byte[] buf = new byte[BufferSize];
			while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
			{
				literalOut.Write(buf, 0, length);
				signatureGenerator.Update(buf, 0, length);
			}

			signatureGenerator.Generate().Encode(compressedOut);
		}

		#endregion WriteOutputAndSign

		#region ChainEncryptedOut

		private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck)
		{
			var encryptedDataGenerator =
				new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
            bool encryptionRun = false;
			foreach (var key in EncryptionKeys.EncryptKeyIds)
			{
				PgpPublicKey publicKey = EncryptionKeys.FindPublicEncryptKey(key);
                if (publicKey == null)
                {
                    continue;
                }
				encryptedDataGenerator.AddMethod(publicKey);
				encryptionRun = true;
			}

            if (!encryptionRun)
            {
                throw new ArgumentException("No encryption key specified in public key ring.");
            }

			return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
		}

		#endregion ChainEncryptedOut

		#region ChainCompressedOut

		private Stream ChainCompressedOut(Stream encryptedOut)
		{
			if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
			{
				PgpCompressedDataGenerator compressedDataGenerator =
					new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
				return compressedDataGenerator.Open(encryptedOut);
			}

			return encryptedOut;
		}

		#endregion ChainCompressedOut

		#region ChainLiteralOut

		private Stream ChainLiteralOut(Stream compressedOut, FileInfo file, string name, bool oldFormat)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator(oldFormat);

            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, file.Length,
				DateTime.UtcNow);
		}

		private Stream ChainLiteralOut(Stream compressedOut, Stream inputStream, string name, bool oldFormat)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator(oldFormat);
			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, inputStream.Length,
				DateTime.UtcNow);
		}

        #endregion ChainLiteralOut

        #region InitSignatureGenerator

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
        {
			var keyMaterial = EncryptionKeys.FindSecretSignKey(EncryptionKeys.SignKeyId);

            PublicKeyAlgorithmTag tag = keyMaterial.NotNull().SecretKey.PublicKey.Algorithm;

			
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithm);
			pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, keyMaterial.NotNull().PrivateKey);
            foreach (string userId in keyMaterial.NotNull().SecretKey.PublicKey.GetUserIds())
			{
				PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
				subPacketGenerator.AddSignerUserId(false, userId);
				pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
				// Just the first one!
				break;
			}

			pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
			return pgpSignatureGenerator;
		}

		#endregion InitSignatureGenerator

		#region InitClearSignatureGenerator

		private PgpSignatureGenerator InitClearSignatureGenerator(ArmoredOutputStream armoredOutputStream)
		{
            var keyMaterial = EncryptionKeys.FindSecretSignKey(EncryptionKeys.SignKeyId);

            PublicKeyAlgorithmTag tag = keyMaterial.NotNull().SecretKey.PublicKey.Algorithm;
			PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithm);
			pgpSignatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, keyMaterial.NotNull().PrivateKey);
			armoredOutputStream.BeginClearText(HashAlgorithm);
			foreach (string userId in keyMaterial.NotNull().SecretKey.PublicKey.GetUserIds())
			{
				PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
				subPacketGenerator.AddSignerUserId(false, userId);
				pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
				// Just the first one!
				break;
			}

			return pgpSignatureGenerator;
		}

		#endregion InitClearSignatureGenerator

		#region Misc Utilities

		private char FileTypeToChar()
		{
			if (FileType == PGPFileType.UTF8)
				return PgpLiteralData.Utf8;
			if (FileType == PGPFileType.Text)
				return PgpLiteralData.Text;
			return PgpLiteralData.Binary;
		}

		private void ExportKeyPair(
			Stream secretOut,
			Stream publicOut,
			PgpSecretKeyRing secretKey,
			PgpPublicKeyRing publicKey,
			bool armor,
			bool emitVersion)
		{
			if (secretOut == null)
				throw new ArgumentException("secretOut");
			if (publicOut == null)
				throw new ArgumentException("publicOut");

			ArmoredOutputStream secretOutArmored;
			if (armor)
			{
				secretOutArmored = new ArmoredOutputStream(secretOut);
				if (!emitVersion)
				{
					secretOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
				}

				secretOut = secretOutArmored;
			}
			else
			{
				secretOutArmored = null;
			}

			secretKey.Encode(secretOut);

			secretOutArmored?.Dispose();

			ArmoredOutputStream publicOutArmored;
			if (armor)
			{
				publicOutArmored = new ArmoredOutputStream(publicOut);
				if (!emitVersion)
				{
					publicOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);
				}

				publicOut = publicOutArmored;
			}
			else
			{
				publicOutArmored = null;
			}
			publicKey.Encode(publicOut);

			publicOutArmored?.Dispose();
		}

		private static int ReadInputLine(MemoryStream streamOut, Stream encodedFile)
		{
			streamOut.SetLength(0);

			int lookAhead = -1;
			int character;

			while ((character = encodedFile.ReadByte()) >= 0)
			{
				streamOut.WriteByte((byte)character);
				if (character == '\r' || character == '\n')
				{
					lookAhead = ReadPassedEol(streamOut, character, encodedFile);
					break;
				}
			}

			return lookAhead;
		}

		private static int ReadInputLine(MemoryStream streamOut, int lookAhead, Stream encodedFile)
		{
			streamOut.SetLength(0);

			int character = lookAhead;

			do
			{
				streamOut.WriteByte((byte)character);
				if (character == '\r' || character == '\n')
				{
					lookAhead = ReadPassedEol(streamOut, character, encodedFile);
					break;
				}
			} while ((character = encodedFile.ReadByte()) >= 0);

			if (character < 0)
			{
				lookAhead = -1;
			}

			return lookAhead;
		}

		private static int ReadPassedEol(MemoryStream streamOut, int lastCharacter, Stream encodedFile)
		{
			int lookAhead = encodedFile.ReadByte();

			if (lastCharacter == '\r' && lookAhead == '\n')
			{
				streamOut.WriteByte((byte)lookAhead);
				lookAhead = encodedFile.ReadByte();
			}

			return lookAhead;
		}

		private static int GetLengthWithoutSeparatorOrTrailingWhitespace(byte[] line)
		{
			int end = line.Length - 1;

			while (end >= 0 && IsWhiteSpace(line[end]))
			{
				end--;
			}

			return end + 1;
		}

		private static int GetLengthWithoutWhiteSpace(byte[] line)
		{
			int end = line.Length - 1;

			while (end >= 0 && IsWhiteSpace(line[end]))
			{
				end--;
			}

			return end + 1;
		}

		private static bool IsWhiteSpace(byte b)
		{
			return IsLineEnding(b) || b == '\t' || b == ' ';
		}

		private static bool IsLineEnding(byte b)
		{
			return b == '\r' || b == '\n';
		}

		private static void ProcessLine(PgpSignature sig, byte[] line)
		{
			// note: trailing white space needs to be removed from the end of
			// each line for signature calculation RFC 4880 Section 7.1
			int length = GetLengthWithoutWhiteSpace(line);
			if (length > 0)
			{
				sig.Update(line, 0, length);
			}
		}

		private static byte[] LineSeparator => Encoding.ASCII.GetBytes(Environment.NewLine);

		public void Dispose()
		{ }

		# endregion Misc Utilities

		#endregion Private helpers
		
	}
}
