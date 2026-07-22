namespace Dhcpr.Dns.Core.Protocol;

public enum DnssecAlgorithmType : byte
{
    RsaMd5 = 1,
    DiffieHellman = 3,
    RsaSha1 = 5,
    DsaNsec3Sha1 = 6,
    RsaSha1Nsec3Sha1 = 7,
    RsaSha256 = 8,
    RsaSha512 = 10,
    EcdsaP256Sha256 = 13,
    EcdsaP384Sha384 = 14,
    Ed25519 = 15,
    Ed448 = 16
}
