using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCoreM.Abstractions
{
    public interface IDecryptAsync : IDisposable
    {
        Task<string> DecryptAsync(FileInfo inputFile, FileInfo outputFile);
        Task<string> DecryptAsync(Stream inputStream, Stream outputStream);
        Task<(string data, string originalFileName)> DecryptAsync(string input);
        Task<string> DecryptAndVerifyAsync(FileInfo inputFile, FileInfo outputFile);
        Task<string> DecryptAndVerifyAsync(Stream inputStream, Stream outputStream);
        Task<(string data, string originalFileName)> DecryptAndVerifyAsync(string input);

        Task<string> DecryptFileAsync(FileInfo inputFile, FileInfo outputFile);
        Task<string> DecryptStreamAsync(Stream inputStream, Stream outputStream);
        Task<(string data, string originalFileName)> DecryptArmoredStringAsync(string input);
        Task<string> DecryptFileAndVerifyAsync(FileInfo inputFile, FileInfo outputFile);
        Task<string> DecryptStreamAndVerifyAsync(Stream inputStream, Stream outputStream);
        Task<(string data, string originalFileName)> DecryptArmoredStringAndVerifyAsync(string input);
    }
}
