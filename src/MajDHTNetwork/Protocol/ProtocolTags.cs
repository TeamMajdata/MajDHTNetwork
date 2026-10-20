using System.Text;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Holds the canonical ASCII protocol labels once, so readers compare bytes instead of decoding strings.</summary>
    public static class ProtocolTags
    {
        /// <summary>The envelope version label, also used as the HKDF domain label.</summary>
        public static readonly byte[] Envelope = Encoding.ASCII.GetBytes("MajDHT/1/envelope");
        /// <summary>The signed contact version label.</summary>
        public static readonly byte[] Contact = Encoding.ASCII.GetBytes("MajDHT/1/contact");
        /// <summary>The signed record version label.</summary>
        public static readonly byte[] Record = Encoding.ASCII.GetBytes("MajDHT/1/record");
        /// <summary>The domain label that separates the agreement key from the signing seed.</summary>
        public static readonly byte[] IdentityAgreement = Encoding.ASCII.GetBytes("MajDHT/1/identity-agreement");
        /// <summary>The placeholder recipient of a Hello request sent before the recipient is known: 64 ASCII zeros.</summary>
        public static readonly byte[] UnknownRecipient = Encoding.ASCII.GetBytes(new string('0', 64));
        /// <summary>The placeholder key of an unencrypted Hello request.</summary>
        public static readonly byte[] EmptyKey = new byte[32];
    }
}
