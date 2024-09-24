using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCoreM.Abstractions
{
    public interface IDecryptSync : IDisposable
    {
        void Decrypt(FileInfo inputFile, FileInfo outputFile, out string originalFileName);
        void Decrypt(Stream inputStream, Stream outputStream, out string originalFileName);
        string Decrypt(string input, out string originalFileName);
        void DecryptAndVerify(FileInfo inputFile, FileInfo outputFile, out string originalFileName);
        void DecryptAndVerify(Stream inputStream, Stream outputStream, out string originalFileName);
        string DecryptAndVerify(string input, out string originalFileName);

        void DecryptFile(FileInfo inputFile, FileInfo outputFile, out string originalFileName);
        void DecryptStream(Stream inputStream, Stream outputStream, out string originalFileName);
        string DecryptArmoredString(string input, out string originalFileName);
        void DecryptFileAndVerify(FileInfo inputFile, FileInfo outputFile, out string originalFileName);
        void DecryptStreamAndVerify(Stream inputStream, Stream outputStream, out string originalFileName);
        string DecryptArmoredStringAndVerify(string input, out string originalFileName);
    }
}
