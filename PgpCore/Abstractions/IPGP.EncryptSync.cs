using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCoreM.Abstractions
{
    public interface IEncryptSync : IDisposable
    {
        void Encrypt(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void Encrypt(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string Encrypt(string input, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptAfterSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptAfterSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string EncryptAfterSign(string input, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);

        void EncryptFile(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptStream(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string EncryptArmoredString(string input, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptFileAfterSign(FileInfo inputFile, FileInfo outputFile, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        void EncryptStreamAfterSign(Stream inputStream, Stream outputStream, bool armor = true, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
        string EncryptArmoredStringAfterSign(string input, bool withIntegrityCheck = true, string name = null, IDictionary<string, string> headers = null, bool oldFormat = false);
    }
}
