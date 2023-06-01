using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using PgpCore;
using Newtonsoft.Json;

namespace ProtonSecrets.StorageProvider
{
    internal static class Crypto
    {
        public static void Sign(byte[] inputStream, Stream signedKeyOutStream, PgpSecretKey signingKey, char[] passphrase, bool armored)
        {
            //InitSignatureGenerator
            PublicKeyAlgorithmTag tag = signingKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha256);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, signingKey.ExtractPrivateKey(passphrase));
            //signedKeyOutStream.BeginClearText(HashAlgorithmTag.Sha1);
            foreach (string userId in signingKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.AddSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }
            pgpSignatureGenerator.Update(inputStream, 0, inputStream.Length);
            if (armored)
            {
                signedKeyOutStream = new ArmoredOutputStream(signedKeyOutStream);
            }
            BcpgOutputStream bcpgOutputStream = new BcpgOutputStream(signedKeyOutStream);
            pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
            if (armored)
            {
                signedKeyOutStream.Close();
            }
            //signedKeyOutStream.Seek(0, SeekOrigin.Begin);
        }

        public static string ComputeFilenameHash(string filename, string decryptedParentNodeHashKey)
        {
            //1. decrypt parent node hashKey
            //2. create a signature of the filename using HMAC and hashKey
            byte[] hashKey = Encoding.UTF8.GetBytes(decryptedParentNodeHashKey);
            using (HMACSHA256 hmac = new HMACSHA256(hashKey))
            {
                byte[] hashValue = hmac.ComputeHash(new MemoryStream(Encoding.UTF8.GetBytes(filename)));
                return Util.ByteArrayToHexString(hashValue);
            }
        }

        //Generate a key suitable for both signing and decryption
        public static PgpSecretKeyRing GenerateKey(char[] passphrase)
        {
            IAsymmetricCipherKeyPairGenerator signing_kpg = new Ed25519KeyPairGenerator();
            signing_kpg.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair newNodeSigningKey = signing_kpg.GenerateKeyPair();
            string username = "Drive key";
            PgpKeyRingGenerator krg = new PgpKeyRingGenerator(
                PgpSignature.DefaultCertification,
                new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa, newNodeSigningKey, DateTime.UtcNow),
                username,
                SymmetricKeyAlgorithmTag.Aes128,
                passphrase,
                true,
                null,
                null,
                new SecureRandom()
                );
            IAsymmetricCipherKeyPairGenerator decrypt_kpg = new X25519KeyPairGenerator();
            decrypt_kpg.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair newNodeEncryptionKey = decrypt_kpg.GenerateKeyPair();
            krg.AddSubKey(
                new PgpKeyPair(PublicKeyAlgorithmTag.ECDH, newNodeEncryptionKey, DateTime.UtcNow),
                HashAlgorithmTag.Sha256
                );
            PgpSecretKeyRing skr = krg.GenerateSecretKeyRing();
            return skr;
        }

        public static string GetArmoredKey(PgpSecretKeyRing skr)
        {
            MemoryStream sOut = new MemoryStream();
            ArmoredOutputStream armoredSOut = new ArmoredOutputStream(sOut);
            skr.Encode(armoredSOut);
            armoredSOut.Close();
            return Encoding.UTF8.GetString(sOut.ToArray());
        }

        public static PgpSecretKey GetSigningKey(PgpSecretKeyRing skr, string passphrase)
        {
            foreach (PgpSecretKey secKey in skr.GetSecretKeys())
            {
                PgpPrivateKey privKey = secKey.ExtractPrivateKey(passphrase.ToCharArray());
                if (privKey.PublicKeyPacket.Algorithm == PublicKeyAlgorithmTag.EdDsa)
                {
                    return secKey;
                }
            }
            return null;
        }

        public static PgpSecretKey GetEncryptionKey(PgpSecretKeyRing skr, string passphrase)
        {
            foreach (PgpSecretKey secKey in skr.GetSecretKeys())
            {
                PgpPrivateKey privKey = secKey.ExtractPrivateKey(passphrase.ToCharArray());
                if (privKey.PublicKeyPacket.Algorithm == PublicKeyAlgorithmTag.ECDH)
                {
                    return secKey;
                }
            }
            return null;
        }

        public static async Task Encrypt(PgpEncryptedDataGenerator pk, Stream input, Stream output, PgpPublicKey pubKey, KeyParameter sessionKey, bool armored)
        {
            pk.AddMethod(pubKey);
            if (armored)
            {
                output = new ArmoredOutputStream(output);
            }
            Stream outStream = null;
            if(sessionKey != null)
            {
                outStream = pk.OpenWithKey(output, 0, new byte[1 << 16], sessionKey);
            }
            else
            {
                outStream = pk.Open(output, 0);
            }
            await Utilities.WriteStreamToLiteralDataAsync(outStream, PgpLiteralData.Binary, input, "");
            outStream.Close();
            if (armored)
            {
                output.Close();
            }
        }

        public static void EncryptAndSign(Stream input, Stream output, PgpPublicKey pubKey, PgpSecretKey signingKey, KeyParameter sessionKey, bool armored, char[] passphrase)
        {
            if (armored)
            {
                output = new ArmoredOutputStream(output);
            }
            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, new SecureRandom());
            encryptedDataGenerator.AddMethod(pubKey);
            Stream outStream = null;
            if(sessionKey != null)
            {
                outStream = encryptedDataGenerator.OpenWithKey(output, 0, new byte[0x10000], sessionKey);
            }
            else
            {
                outStream = encryptedDataGenerator.Open(output, 0);
            }
            PublicKeyAlgorithmTag tag = signingKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha256);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, signingKey.ExtractPrivateKey(passphrase));
            foreach (string userId in signingKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }
            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(outStream);
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            Stream finalOutStream = pgpLiteralDataGenerator.Open(outStream, PgpLiteralData.Binary, "", input.Length, DateTime.UtcNow);
            int length;
            byte[] buf = new byte[0x10000];
            while ((length = input.Read(buf, 0, buf.Length)) > 0)
            {
                finalOutStream.Write(buf, 0, length);
                pgpSignatureGenerator.Update(buf, 0, length);
            }

            pgpSignatureGenerator.Generate().Encode(outStream);
            outStream.Close();
            if (armored)
            {
                output.Close();
            }
        }

        public static async Task<string> EncryptFileExtendedAttributes(int size, PGP keys)
        {
            int FILE_CHUNK_SIZE = 4 * 1024 * 1024;
            List<int> blockSizes = new List<int>();
            int listLength = (int)Math.Floor((double)size / (double)FILE_CHUNK_SIZE);
            for (int i = 0; i < listLength; i++)
            {
                blockSizes.Add(FILE_CHUNK_SIZE);
            }
            blockSizes.Add(size % FILE_CHUNK_SIZE);
            Dictionary<string, dynamic> xAttr = new Dictionary<string, dynamic>()
            {
                {
                    "Common",
                    new Dictionary<string, dynamic>[]
                    {
                        new Dictionary<string, dynamic>()
                        {
                            {"ModificationTime", DateTime.UtcNow.ToString("o", System.Globalization.CultureInfo.InvariantCulture) },
                            {"Size", size },
                            {"BlockSizes", blockSizes.ToArray() }
                        }
                    }
                }
            };
            string xAttrString = JsonConvert.SerializeObject(xAttr);
            keys.CompressionAlgorithm = CompressionAlgorithmTag.ZLib;
            keys.HashAlgorithmTag = HashAlgorithmTag.Sha256;
            return await keys.EncryptArmoredStringAndSignAsync(xAttrString);
        }
    }
}
