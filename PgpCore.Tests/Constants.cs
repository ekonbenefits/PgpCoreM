﻿using System;
using System.Collections.Generic;
using System.Text;

namespace PgpCoreM.Tests
{
    public static class Constants
    {
        // Known keys, generated using https://pgpkeygen.com/
        public const string PUBLICKEY1 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xo0EXRzQ9gEEALWy0pmWiNwti765q5l/cgohqa5fKBZWy2VggB8YlLNSGaiR4Esd
Ya0+SSkwe0C3O9xjzUlQA/0SGYelxjgYhxqTyvLiVKKTx6HE1FW6PPrYMK4+GQaH
SfhO5ILLqXx0/o7XF77qSmxdrcQrIwNhdeOwDBDOrwLWDuU+Gx/F9AU9ABEBAAHN
I2VtYWlsMUBlbWFpbC5jb20gPGVtYWlsMUBlbWFpbC5jb20+wq0EEwEKABcFAl0c
0PYCGy8DCwkHAxUKCAIeAQIXgAAKCRAy61veQBr1zRx8A/43SUeO5lGjksMbZuqp
fiJFdjd3aT94jz7oukfUL/t+ToVtxRRSTr6aoYVclK21TP797zme86zsmM3fUKzO
nVCs4V4E9c7lz69hd2+PBhDX29a7fywFWOQ5dAavuHUAw8akLZdY7sWh720Gbh8Q
3GRdrUry78nmkAWuw8JBh71uX86NBF0c0PYBBADW3E+IuxoDxc1CSJBL8iLc4A9L
3FpWeifBbq5PCpjYcqodb1FvD5eaqYgqf5/hPQLdRP/XRHtKKkph+XdF5Wrx0AMC
sEgr6JZ3SicobLev028DADYugJcZ9E1T/nkkkggamQBX5ryxB6X8se0m27QTd06n
KIhN67qCX/Gi+3UkmwARAQABwsCDBBgBCgAPBQJdHND2BQkPCZwAAhsuAKgJEDLr
W95AGvXNnSAEGQEKAAYFAl0c0PYACgkQHCBL6iCIoI+EhQP+OgbEfsQwixiyVQaG
1D+RSAGAnARX2Y+VatAtRsWuEXNYeNjFsPDMRbgtoCfrAlQoL0wXQXu+TXOu9xkL
u3hq4Nd8+fvvE1znc1zT7Ie1Tb20luA7Qzk3lQV4w2nxpXL3hl7JN1KxmPwanrQv
bT99eh9lhceoQHls/g1+sjOtQ4Kr1wQAnUMopnAavdlnfpJYXTqHH6QI4uBYscNH
ZHa5OdLgFBzBx+IGvYpDZzTjxuAmbVvQZIkJi4iI0xua/ER/AJIdYgSUTbKT7nif
f8neNHVvJGTF1iYoORMFrQEjnYPwRaEnzMpLkCryBsGFjYfj1X2wrzNL5dEzU97M
R2qeFsfC3szOjQRdHND2AQQAp1m2xMs34pmeVzGqbmRcoASe+MHazJyv+L+XhEF0
OxThH4NKLJLXotib9KXZlgqfiETgmRvoLeQvBu2f/5Nf5TgGITcS8/0jyvolwv+9
IRPxXRBXbk3H89z5UqVFa2FkEnS21wQUMRYqUEzO1n04ImhAWOUDF3b8eOT1q2+A
HnMAEQEAAcLAgwQYAQoADwUCXRzQ9gUJDwmcAAIbLgCoCRAy61veQBr1zZ0gBBkB
CgAGBQJdHND2AAoJEEdOvSYcuM90w1YD/3XCcndLA4OIF7cJlo1DbPkN3cwtldvT
vyvf9n7G5epB99/wNjDrWzzFXWU+3oOOwnnQXk9oZoWOPmMp02OlZW7s3WLWj5ZQ
0RoEzM3cQRdpTU1oX02zNKoMGcHY5Tfiacfvr/EZx3ElsyZ81zIR0HtyXMwRrgTg
A4KsnnILrp6JpVkD/20JllnAfq7xIqGpQCFCs1CxYYDEfEuqxcQf+wpdICG6FqRn
P4IOoqsVnY2EEHwdr9VjKyf6L+Pd2PLou8pWCu6rF/M3zIjAwzzPsJ5/AlINTql0
b8xSWNM02DrVx932kcSOx4k8BaZ0IiSwzny4xZEoOIPKK8SZ+EZeZaeopZ7h
=O3ub
-----END PGP PUBLIC KEY BLOCK-----";

        public const string PUBLICKEY2 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

xo0EXRzR8gEEAOJguWTfef08UottAIqsBxYh0Cea7QF4toOdSCOXwT70pY+uiwVj
gMgd1IqI8/uZg2orYsI2+6SYUjyNbYXOMIBgLt7LNz2Xu//RCqcVgdhpgusXnQoI
ru+BoT1H0IcgGAmwQ1MxvvTX5MmcDpzRBgNkpfQIsohmnYsX46GzYUpjABEBAAHN
I2VtYWlsMkBlbWFpbC5jb20gPGVtYWlsMkBlbWFpbC5jb20+wq0EEwEKABcFAl0c
0fICGy8DCwkHAxUKCAIeAQIXgAAKCRDHOc/0fnhNpuFhBAChzcCOwhGnNZTV2xFB
8CXbAt6mEfuxgcVdiKEKNZvvk75HJKmN0/5hW9ubfIGpu4oxsfFV7DEElKpCoj6K
513kM9J32wmfzx49mRJYXsMFeResF3XS1qN7JfY0o/vrI3HZAFwA2xddkK4NkXl+
r1TXO+VrJrW4FAc34a2OCGb5w86NBF0c0fIBBADSE2B/pYRFSSVmbuqQM+37BZhm
Hwk1aXlHVpX4IKV65SzVID9qrub2PrwClRdm1q+1wuaiEaWsT2obYRXLaXfsWb6F
3g9gumIoMd7k1T8rUsmVgddroyegtPsEFSNcSGtFKpBVwhMznTMqBkr4QMLxAyw0
fOSwag0Rc2ipBW+i/wARAQABwsCDBBgBCgAPBQJdHNHyBQkPCZwAAhsuAKgJEMc5
z/R+eE2mnSAEGQEKAAYFAl0c0fIACgkQUI7UIwZpecWdvwP9FekQEnaxm3i+Sevv
B8MQlIzuypOWBIqTWx8Xcw/ldkFZDfujFHBIvLULMXNxO8rrsRXii5w1gR0xVj5A
mxTp6v+q2z+fmRoVr0Ym/r/chNlkbR4Jle+QckPeSnhKMZEfLmB4D4K6tX4CUCSF
EoIx6oWWeIbTdeNCQnHvbGALpEkDIwQAx0ihTWXggVZXaCtyOFVJKwCK8EPKu3pR
vK64vzoNqlqxd7F8Qhzo971aR9vTOvS4CV78ovQFX02TZGHocRWZx1mGdrlVPZWp
OlzHR0vT0psBSvaFWqkaifOScEQ0ATKguJNvo+kHOKBW3p/F6zrzqcG94RCPkHf2
MrSSQubDtOfOjQRdHNHyAQQAu5YHRDMFBLa7afjPtkMooybqM1KSeC62jByXReRT
EfVIgRDdI+1p19z/hPBz//OSU0kN6ePrhYSlIvhT74Nk8CTpvAwpS1791SC7mwxU
wZK5jNMi5HrfOlGwlhasdSe+v3xiSbSkHEtwPscBbyBWSqqGZbZIkk1OfjtBcK3P
55kAEQEAAcLAgwQYAQoADwUCXRzR8gUJDwmcAAIbLgCoCRDHOc/0fnhNpp0gBBkB
CgAGBQJdHNHyAAoJEEbXCPn6ISugs+kD/340wN26UWPXEJUugy+yjpixYkU3T6vS
V0QzF3188TEUhrVd6TBVea7HBQOsg+aSZQTrEICfcmif6zmJ9r+6Q5BNuIc8wy7G
zkBJ7kR/XyfAHN5MNLfdBnHSZZqRwIbrm4rVNIOjXhLVUNaOF3v9wlor7JNVoXP/
+3yMMp8k32a28HUEAN988ZbipEZFyZjhZWPQbpuNA0LxRiqV4HMoCiJ+jBM3lGVp
O3IEvHTXyUErcgSBekr3BhIuHTHwt9RWTVNWBku8UsX9Ao1M8vRWimNwIlGdBrIT
iSJGzF6qhiiorxaJkMNx7xDgxQFZgHiihjIsolKego98NLI8e9j7+6zOHR0f
=lgvU
-----END PGP PUBLIC KEY BLOCK-----";

        public const string PRIVATEKEY1 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

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
BaZ0IiSwzny4xZEoOIPKK8SZ+EZeZaeopZ7h
=i6tW
-----END PGP PRIVATE KEY BLOCK-----";

        public const string PRIVATEKEY2 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: Keybase OpenPGP v1.0.0
Comment: https://keybase.io/crypto

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
AVmAeKKGMiyiUp6Cj3w0sjx72Pv7rM4dHR8=
=dUJo
-----END PGP PRIVATE KEY BLOCK-----";

        public const string PUBLICGPGKEY1 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF757qEBCADD5rzakxbG3hjPN3jGuqHuwSzPBPJwDcWMACFXhou37+qet2JM
V3sk77vylvMU0egA5ag57KPDmQr2SSehpQ4tophd0Gi9Ut9nfy4xMdcO0oaId5wo
ao1MEGWfQdV41yqZr5YQLxHK0UaYO32wiD87jMVRV18N1YMcloDuty/XdANt2mAh
I8Dc8C+x9y+SDqvsEfcs4GWDpypVUjiSpMu2X0WxfadrNnxucTT4AJ0yByPNyNN5
bwT9t9/4Fe69o7a8XyzXA/BbpjVfCH9jwwDlsxP2+BBR85RmulR6QQp5KcrRUK4h
BXtWh693UK6FthgQz/Kmeky79diwtF4pnT8TABEBAAG0EGVtYWlsMUBlbWFpbC5j
b22JAVQEEwEIAD4WIQR6+b/bTEla7bXhfgCEEA/vqwuHPQUCXvnuoQIbAwUJA8Jn
AAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCEEA/vqwuHPfO2B/9UayAFPL27
ZzWlsuQJRGOFpANQzmJ4wLgrNCqfGOqD4hC7AotgMTThGA535goNjLcNKn0thU7z
Z0g7XO2wZoCPEpH0uLBzYuxKtGbiGur8PRtFZVCsIqVUOaDkbSdYjPqzNk23c2Oa
a4WADMmmartFDVoaLNdbPG3c4XUSnyAA9YAonPnibr7y/SFoyHjpBcNlZoAl8l/E
HrusAbkPaRO1GD/9mXZJK9YbeEy+4F9dYXiqjOU11x4f2bdwDsW4wUBhPE2OeZ3j
iIYaMGi/GxVHlQLIob97Wwh39lGR0V7MV6GUG7rzNBl1bn22nXUQWFg7+EtmOGu8
VcT6SgyU+wCeuQENBF757qEBCACecC8/ARg2sVzCuzGh6+RXFVJbKck0IwKuO7Xi
OFHqUKmbjqFSIgMuNanvqwZJsfm+ZxqpU7hlDAzpb/uou1ebjbDw5TiBxQUajJeH
7bBjgIe67cfRH4ajjc6oLseUlOqLXErThlu3tS7kEOu/yRCbzVOKErJUAW5FeXQS
1vs2ceYYrv/ATl317RJ3lXiAKGm5ZIcJBV49fspB5wW98Yavf19GKSP6ij1XI6PG
gVHxWGszweXjr8cR07LR/K3hwWELYM/SzBttUAydURlyseRCiDpdMDwDkBxAwYZf
ZfG+k1I2mKbbTJmm+qnLQ0hchNkOCkW20bRxGOOuDrzieup3ABEBAAGJATwEGAEI
ACYWIQR6+b/bTEla7bXhfgCEEA/vqwuHPQUCXvnuoQIbDAUJA8JnAAAKCRCEEA/v
qwuHPUjoB/445UUapUS+IiPqH0CWMd5ZWsrt2GUwBYiNyf2sOvDAg65JyhWemh9Z
aCHXdk0lAaepggbRxJ1yWrzLO1jDyjiv6ebGjnMCoZsG7OB9vrEwiHpYdt7garCd
ssBIpig/4mo1yZWWN2DZMGIB8LV0C9fflGkouyNUzaF1C/xC5Hyf1iBkB3kpw2L8
fS9sQel74Hl3xocpXCiq5aK8sidv0EcjXJsx2NZSPeibIMLmXi0OXpz0ktZbBRmN
KnBTfT0klcOd5G0dn8wosUZnZjfLptgMNgATb7p0FoOUUI5qte2JIKQWpopeC5tr
KouLiF6zJ1bwxlnNeabP/z+Lm8K4V328
=nm1p
-----END PGP PUBLIC KEY BLOCK-----";

        public const string PUBLICGPGKEY2 = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF04J+YBCADdpMrZ2j2rzwWAU+b8d6CUpE+W7IpY/0/ZZjD6yinyiHou7T56
PUbr1vA0E+GjNM+iLhG4BdxJhkU3F1HJ2j6kFHP2iupkVYFs0jGEtO0wHpFpyrun
eOrEwWXHMn4SjR4a1Sjo/WWJi8Q9klypaTinPgbq45Sn4XRTXrAHwV/edKSBbFZ/
MDq2bPnHpy22AVoA3h78pbEShbIcpMa1fr9iVjhEwYK2oRsx/LqXmHBlE/+tf1WB
hkmV1lxRhMv6ZtLTB3DpmSMkrIyP6yy4+b++dwd3PX21UJlYYE3Ivv+wDie/nkbc
+uDs+RLeNfwVSAzhKdch6gsz+xtww+zN6Lu5ABEBAAG0Hm1hdHRvc2F1cnVzIDxl
bWFpbDJAZW1haWwuY29tPokBVAQTAQgAPhYhBLorJjEIguwDBiVJmM8lFD3YPt2S
BQJdOCfmAhsDBQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEM8lFD3Y
Pt2SObwIALkoUY29RZDN0DzC4BexldMBQuGJzAF/Peaf8A0FUvE+xNoXgcHzFIPB
zI3vAUd09cxYc6EXhMxQi4mEVzTluAtuMO1y6dXYFflPL7LRKgdiZSW3GMcpn3Yy
2osbUX2w0HJMUjdtuZHS5aYnFRFGVCDF9QbXb5JP9atYJud0yjY6nKh3pCkUdPLC
2EhebmmZsEZyHvuThRQ1g7ZPpX01tAFrxZ4E2B2bZa67uQDOvqdTgZnT5GeOPcqb
5hsHwzFIivd76I2fdQn3PK0KoDJ6X+0embKJZTno6mr9WTGHfu5pO/7FtoUufjdt
NDp4rSaYmDpdPwLLPYQNM9tG6g503qO5AQ0EXTgn5gEIALvG66UdJIYV8k6PWxPT
gt45qphgzPSfgbV1VwXLbNOK3hRf3AtrVjCbFjeBT82eVeG4Q4WRmPSaShOzGzve
Wcr0YTU3QOfr4k6Z8oldYkDPDbJ4PpK+u+NgVspzjrPoCQhUi490OunDDupnCKET
e8DzIrE2QQ2pCruhjFBZPRTbq1zlhcJ6Xhf1OVW7VcCaaFZ+N9pBbjhXAc4frs+/
JZhKBVWCMM04DWvHjeEPKoXRivZviHy6os5OUYts+BlWLHkIv2XM8FqjGdlM4s7v
s9sTNT6LupG+dcgo4CYuax5Rh7KrS5P3pHSKaffaEB++ho+Gi8p9jJ2DY8MTwTlv
tr0AEQEAAYkBPAQYAQgAJhYhBLorJjEIguwDBiVJmM8lFD3YPt2SBQJdOCfmAhsM
BQkDwmcAAAoJEM8lFD3YPt2SIOwH/1MH0waFa6zRapYr1uSNANAWnB1yHFtMQgt/
wxHteAThbDKkH68hpNY+MsMAlopLNb5dzSbwa8rzqIGf9+gTr3ZCOO8LoNrrurQf
4bgNi87QT+if1euRE4bMBG++ztyHj7tf2sDAufr30cGJ/1Kk44mgp/ZPelN8bgQ3
/pJEcFQdvS92Aqb6ZoDS0Vj/iSEowXSKzxWmNmF5O2RBIv+pEHAyTes8vrIsU3zf
AP5/T4AbSvis6g4hE9vS/whp4tARY7D7WjFXFWD3fIAiC0KHZPUudy2g8Hcwr5M9
pCNCbkyRFW+kY0x8hZKez3AsiXtDSiDG9WD1NbrUvEAxaf2MkSU=
=LNCL
-----END PGP PUBLIC KEY BLOCK-----";

        public const string PRIVATEGPGKEY1 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
m2sqi4uIXrMnVvDGWc15ps//P4ubwrhXfbw=
=drdt
-----END PGP PRIVATE KEY BLOCK-----";

        public const string PRIVATEGPGKEY2 = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=tfnh
-----END PGP PRIVATE KEY BLOCK-----";

        public const string ENCRYPTEDCONTENT1 = @"-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

wcBMA+cxhM+dKt4UAQgA6MiSXq2KSOlAsGFl2DrCp/j7CIeFBSxc/elikmS0
9jvYV8yhTZ6F3N1Cj1tDQZ18d7Ih5npRkCXlCMKijTRJ6T4gChQ/rIAtA1hr
tSjz8UzHFetFxiXCacWUNK+Q1WRG7CKfClvF9tOBrG6WmKwkY+KzbDQ0vRzQ
1JRnHAfJ++fq5y3mJIlUoCNhgYMl5vDvr6rkGW7bFjFfB6amLdIHZn9Tc3GV
jRG6v5MxqAppEsqIhEgr17/6qSslU/IFTokNNsd0OTGTzTejmY49SPM3O6e9
Ou2hqUPPRovNuhqOtys6HpMU+mesprrdx6a7OeWnlDvCkg3N37LLpssyHqum
kNJjAaHUdUGuuQ8ZCtuu7NC/LdfCGu+WT0iQAR9kdLTwNOq1TgsYu68TEX1u
Dq3YVTdbdAF/uURDx4aexQDVTq8IDk32FwVSaES6PG5qCgR0RCkwkJGxruhT
sZg/AsVo3z+/sr7a
=4Wwg
-----END PGP MESSAGE-----";

        public const string ENCRYPTEDCONTENT2 = @"-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v3.0.9
Comment: https://openpgpjs.org

wcBMA9QtMjxDkm//AQf6Aqxd0fr81dBjxP892DEtC9Nwq2AXFgBAnAlhTGIr
8zPrtr12V5V6aTOZ0IChldtsaEGwxVrodFhqWO4WKlFrpVon86RglOednHU/
/sJNbdsnW3t8dUbD8k8V+5pkba+oX6iklvzv8hpqAEMc7Gwp7fMcDPF00BkY
mhIBvZXpCbLRtQt/K4qo3kpRqZDJSWKGtGPtXDGtx7duCxR41ArleQjfGyxN
Be5bWPu0/gZWMkew62PFTDIqeBfRR7+V1PMRhwL0WJdgOqhRoDkNQhUPJ7aa
ALSy//blnbktrSZrR7vWo3lm2ZGFl0uzcpBM3pcFFMssieOPi+E7IovfZTW0
O9JjAUTVXka99zj8wPlezPqUsekTIhgVw5vso4gJTz3DsJR0jtTIWczgp5+U
1hay6pEQUCGasIB5OWQImpKmTNEHmv+jvXskuk4kuPy7gqOiWcN34XTmGGbz
MFHwXEtblMhDz7ni
=navA
-----END PGP MESSAGE-----";

        public const string USERNAME1 = "email1@email.com";
        public const string USERNAME2 = "email2@email.com";
        public const string PASSWORD1 = "password1";
        public const string PASSWORD2 = "password2";
        public const string CONTENTBASEDIRECTORY = "./Content/";
        public const string KEYBASEDIRECTORY = "./Keys/";
        public const string CONTENT = "The quick brown fox jumps over the lazy dog";
        public const string CONTENTFILENAME = "content.txt";
        public const string ENCRYPTEDCONTENTFILENAME = "encryptedContent.pgp";
        public const string SIGNEDCONTENTFILENAME = "signedContent.pgp";
        public const string DECRYPTEDCONTENTFILENAME = "decryptedContent.txt";
        public const string PRIVATEKEYFILENAME = "privateKey.asc";
        public const string PUBLICKEYFILENAME = "publicKey.asc";
    }
}
