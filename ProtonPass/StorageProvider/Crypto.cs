using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using PgpCore;
using Newtonsoft.Json;

namespace ProtonPass.StorageProvider
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
                outStream = pk.Open(output, new byte[1 << 16]);
            }
            await Utilities.WriteStreamToLiteralDataAsync(outStream, PgpLiteralData.Binary, input, "");
            outStream.Close();
            if (armored)
            {
                output.Close();
            }
        }

        public static async Task<string> EncryptArmoredStringAndSignAsync(string input, PgpPublicKey publicKey, KeyParameter sessionKey, PgpSecretKey signingKey, char[] passphrase, bool compressed = false)
        {
            using (Stream inputStream = await input.GetStreamAsync())
            using (Stream outputStream = new MemoryStream())
            {
                await EncryptStreamAndSignAsync(inputStream, outputStream, publicKey, sessionKey, signingKey, passphrase, true, compressed);
                outputStream.Seek(0, SeekOrigin.Begin);
                return await outputStream.GetStringAsync();
            }
        }

        public static async Task EncryptStreamAndSignAsync(Stream inputStream, Stream outputStream, PgpPublicKey publicKey, KeyParameter sessionKey, PgpSecretKey signingKey, char[] passphrase, bool armor = true, bool compressed = false)
        {
            if (armor)
            {
                using (var armoredOutputStream = new ArmoredOutputStream(outputStream))
                {
                    await OutputEncryptedAsync(inputStream, armoredOutputStream, publicKey, sessionKey, signingKey, passphrase, compressed);
                }
            }
            else
                await OutputEncryptedAsync(inputStream, outputStream, publicKey, sessionKey, signingKey, passphrase, compressed);
        }

        public static async Task OutputEncryptedAsync(Stream inputStream, Stream outputStream, PgpPublicKey publicKey, KeyParameter sessionKey, PgpSecretKey signingKey, char[] passphrase, bool compressed = false)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, publicKey, sessionKey))
            {
                using (Stream compressedOut = ChainCompressedOut(encryptedOut, compressed))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, signingKey, passphrase);
                    using (Stream literalOut = ChainLiteralStreamOut(compressedOut, inputStream))
                    {
                        await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
                    }
                }
            }
        }

        public static Stream ChainEncryptedOut(Stream outputStream, PgpPublicKey publicKey, KeyParameter sessionKey)
        {
            var encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes128, true, new SecureRandom());

            encryptedDataGenerator.AddMethod(publicKey);

            if (sessionKey != null)
            {
                return encryptedDataGenerator.OpenWithKey(outputStream, 0, new byte[0x10000], sessionKey);
            }
            else
            {
                return encryptedDataGenerator.Open(outputStream, new byte[0x10000]);
            }
        }

        public static Stream ChainCompressedOut(Stream encryptedOut, bool compressed = false)
        {
            if (compressed)
            {
                PgpCompressedDataGenerator compressedDataGenerator =
                    new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                return compressedDataGenerator.Open(encryptedOut);
            }

            return encryptedOut;
        }

        public static PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, PgpSecretKey signingKey, char[] passphrase)
        {
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
            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
            return pgpSignatureGenerator;
        }

        public static Stream ChainLiteralStreamOut(Stream compressedOut, Stream inputStream)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, PgpLiteralData.Binary, "", inputStream.Length, DateTime.UtcNow);
        }

        private static async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, Stream inputStream, PgpSignatureGenerator signatureGenerator)
        {
            int length;
            byte[] buf = new byte[0x10000];
            while ((length = await inputStream.ReadAsync(buf, 0, buf.Length)) > 0)
            {
                await literalOut.WriteAsync(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOut);
        }

        public static async Task<string> EncryptFileExtendedAttributes(int size, PgpPublicKey pubKey, PgpSecretKey signingKey, char[] passphrase)
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
            MemoryStream encryptedXAttr = new MemoryStream();
            return await EncryptArmoredStringAndSignAsync(xAttrString, pubKey, null, signingKey, passphrase, true);
        }
    }
}
