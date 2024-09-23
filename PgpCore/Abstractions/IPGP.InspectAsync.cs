using System;
using System.IO;
using System.Threading.Tasks;
using PgpCoreM.Models;

namespace PgpCoreM.Abstractions
{
    public interface IInspectAsync : IDisposable
    {
        Task<PgpInspectResult> InspectAsync(Stream inputStream);
        Task<PgpInspectResult> InspectAsync(FileInfo inputFile);
        Task<PgpInspectResult> InspectAsync(string input);
    }
}
