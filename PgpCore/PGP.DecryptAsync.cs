using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCoreM.Extensions;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PgpCoreM.Abstractions;
using PgpCoreM.Helpers;
using PgpCoreM.Models;
using System.Data;

namespace PgpCoreM
{
    public partial class PGP : IDecryptAsync
    {
        #region DecryptAsync

        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file</param>
        /// <param name="outputFile">Output PGP decrypted file</param>
        public async Task<string> DecryptAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Encryption Key not found.");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                return await DecryptAsync(inputStream, outStream);
        }

        /// <summary>
        /// PGP decrypt a given stream.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream</param>
        /// <param name="outputStream">Output PGP decrypted stream</param>
        /// <returns></returns>
        public async Task<string> DecryptAsync(Stream inputStream, Stream outputStream)
        {
            string originalFileName;
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("OutputStream");

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            PgpObject obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            PgpObject message = null;

            if (obj is PgpEncryptedDataList dataList)
                enc = dataList;
            else if (obj is PgpCompressedData compressedData)
                message = compressedData;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            using (CompositeDisposable disposables = new CompositeDisposable())
            {
                // decrypt
                (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? privateKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                if (enc != null)
                {
                    foreach (var publicKeyEncryptedData in enc.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>())
                    {
                        privateKey = EncryptionKeys.FindSecretDecryptKey(publicKeyEncryptedData.KeyId);

                        if (privateKey != null)
                        {
                            pbe = publicKeyEncryptedData;
                            break;
                        }
                    }

                    if (privateKey == null)
                        throw new ArgumentException("Secret key for message not found.");

                    Stream clear = pbe.GetDataStream(privateKey.NotNull().PrivateKey).DisposeWith(disposables);
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    message = plainFact.NextPgpObject();

                    if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                    {
                        message = plainFact.NextPgpObject();
                    }
                }

                if (message is PgpCompressedData pgpCompressedData)
                {
                    Stream compDataIn = pgpCompressedData.GetDataStream().DisposeWith(disposables);
                    PgpObjectFactory objectFactory = new PgpObjectFactory(compDataIn);
                    message = objectFactory.NextPgpObject();

                    if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                    {
                        message = objectFactory.NextPgpObject();
                        var literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        originalFileName = literalData.FileName;
                        await StreamHelper.PipeAllAsync(unc, outputStream);
                    }
                    else
                    {
                        PgpLiteralData literalData = (PgpLiteralData)message;
                        Stream unc = literalData.GetInputStream();
                        originalFileName = literalData.FileName;
                        await StreamHelper.PipeAllAsync(unc, outputStream);
                    }
                }
                else if (message is PgpLiteralData literalData)
                {
                    Stream unc = literalData.GetInputStream();
                    originalFileName = literalData.FileName;
                    await StreamHelper.PipeAllAsync(unc, outputStream);

                    if (pbe.IsIntegrityProtected())
                    {
                        if (!pbe.Verify())
                        {
                            throw new PgpException("Message failed integrity check.");
                        }
                    }
                }
                else if (message is PgpOnePassSignatureList)
                    throw new PgpException("Encrypted message contains a signed message - not literal data.");
                else
                    throw new PgpException("Message is not a simple encrypted file.");
            }

            return originalFileName;
        }

        /// <summary>
        /// PGP decrypt a given string.
        /// </summary>
        /// <param name="input">PGP encrypted string</param>
        public async Task<(string data, string originalFileName)> DecryptAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                var originalFileName = await DecryptAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return (await outputStream.GetStringAsync(), originalFileName);
            }
        }

        public async Task<string> DecryptFileAsync(FileInfo inputFile, FileInfo outputFile) => await DecryptAsync(inputFile, outputFile);

        public async Task<string> DecryptStreamAsync(Stream inputStream, Stream outputStream) => await DecryptAsync(inputStream, outputStream);

        public async Task<(string data, string originalFileName)> DecryptArmoredStringAsync(string input) => await DecryptAsync(input);

        #endregion DecryptAsync

        #region DecryptAndVerifyAsync

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message. 
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="inputFile">PGP encrypted data file path to be decrypted and verified</param>
        /// <param name="outputFile">Output PGP decrypted and verified file path</param>
        public async Task<string> DecryptAndVerifyAsync(FileInfo inputFile, FileInfo outputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (outputFile == null)
                throw new ArgumentException("OutputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            using (Stream inputStream = inputFile.OpenRead())
            using (Stream outStream = outputFile.OpenWrite())
                return await DecryptAndVerifyAsync(inputStream, outStream);
        }

        /// <summary>
        /// PGP decrypt and verify a given file.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message. 
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="inputStream">PGP encrypted data stream to be decrypted and verified</param>
        /// <param name="outputStream">Output PGP decrypted and verified stream</param>
        public async Task<String> DecryptAndVerifyAsync(Stream inputStream, Stream outputStream)
        {
            var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            var encryptedDataList = objFactory.NextPgpObject() as PgpEncryptedDataList;
            // the first object might be a PGP marker packet.
            if (encryptedDataList is null)
            {
                encryptedDataList = objFactory.NextPgpObject() as PgpEncryptedDataList;
            }

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (encryptedDataList == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            using CompositeDisposable disposables = new CompositeDisposable();
            // decrypt
            (PgpPrivateKey PrivateKey, PgpSecretKey SecretKey)? privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;

            foreach (var publicKeyEncryptedData in
                     encryptedDataList.GetEncryptedDataObjects().OfType<PgpPublicKeyEncryptedData>())
            {
                privateKey = EncryptionKeys.FindSecretDecryptKey(publicKeyEncryptedData.KeyId);

                if (privateKey != null)
                {
                    pbe = publicKeyEncryptedData;
                    break;
                }
            }

            if (privateKey == null)
            {
                throw new MissingPrimaryKeyException("Secret key for message not found.");
            }

            Stream clear = pbe.GetDataStream(privateKey.NotNull().PrivateKey).DisposeWith(disposables);

            PgpObjectFactory plainFact = new PgpObjectFactory(clear);

            var message = plainFact.NextPgpObject();
            if (message is PgpCompressedData cData)
            {
                Stream compDataIn = cData.GetDataStream().DisposeWith(disposables);
                plainFact = new PgpObjectFactory(compDataIn);
                message = plainFact.NextPgpObject();
            }

            var sList = message as PgpOnePassSignatureList;
            if (sList is null)
            {
                throw new PgpException("File was not signed.");
            }

            PgpPublicKey verifyKey = null;
            int sigIndex = 0;
            for (int i = 0; i < sList.Count; i++)
            {
                var ops1 = sList[i];
                verifyKey = EncryptionKeys.FindPublicVerifyKey(ops1.KeyId);
                if (verifyKey != null)
                {
                    sigIndex = i;
                    break;
                }
            }

            if (verifyKey is null)
            {
                throw new PgpException("Failed to verify file.");
            }


            var literalData = plainFact.NextPgpObject() as PgpLiteralData;
            if (literalData is null)
            {
                throw new InvalidDataException("Unable to Parse File.");
            }
            var matchList = plainFact.NextPgpObject() as PgpSignatureList;
            if (matchList is null)
            {
                throw new PgpException("File was not signed.");
            }
            var unc = literalData.GetInputStream().DisposeWith(disposables);
            var originalFileName = literalData.FileName;
            var ops = sList[sigIndex];
            var match = matchList[sigIndex];
            ops.InitVerify(verifyKey);
            await StreamHelper.PipeAllOnPassVerifyAsync(unc, outputStream, ops, match);
            return originalFileName;
        }

        /// <summary>
        /// PGP decrypt and verify a given string.
        /// This method will only work with a file that was encrypted and signed using an EncryptAndSign method as in this case the signature will be included within the encrypted message. 
        /// It will not work with a file that was signed and encrypted separately in a 2 step process.
        /// </summary>
        /// <param name="input">PGP encrypted string to be decrypted and verified</param>
        public async Task<(string data, string originalFileName)> DecryptAndVerifyAsync(string input)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                var originalFileName  = await DecryptAndVerifyAsync(inputStream, outputStream);
                outputStream.Seek(0, SeekOrigin.Begin);
                return (await outputStream.GetStringAsync(), originalFileName);
            }
        }

        public async Task<string> DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile) => await DecryptAndVerifyAsync(inputFile, outputFile);

        public async Task<string> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream) => await DecryptAndVerifyAsync(inputStream, outputStream);

        public async Task<(string data, string originalFileName)> DecryptArmoredStringAndVerifyAsync(string input) => await DecryptAndVerifyAsync(input);

        #endregion DecryptAndVerifyAsync
    }
}
