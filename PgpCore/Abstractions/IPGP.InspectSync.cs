using System;
using System.IO;
using PgpCoreM.Models;

namespace PgpCoreM.Abstractions
{
    public interface IInspectSync : IDisposable
    {
        PgpInspectResult Inspect(Stream inputStream);
        PgpInspectResult Inspect(FileInfo inputFile);
        PgpInspectResult Inspect(string input);
    }
}
