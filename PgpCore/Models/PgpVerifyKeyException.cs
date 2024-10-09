using System;
using System.Collections.Generic;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpCoreM;

public class PgpVerifyKeyException : PgpException
{

    public PgpVerifyKeyException(string message) : base(message)
    {

    }   
    public PgpVerifyKeyException(string message, Exception innerException) : base (message, innerException)
    {

    }

    public List<string> SignatureFullKeyIds { get; } = new();
};