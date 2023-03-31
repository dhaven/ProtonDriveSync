

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;

using static BCrypt.Net.BCrypt;
using System.IO;
using Org.BouncyCastle.Tls;

namespace ProtonSecrets.StorageProvider
{
    public static class Util
    {
        public static string SRP_MODULUS_KEY = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

                xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
                L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
                BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
                MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD / V6NglBd96lZKBmInSXX / kXat
                Sv + y0io + LR8i2 + jV + AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9 + KfE
                kSIgcBRE3WuXC4oj5a2 / U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
                hcTpUY8mAhsMAAD / XQD8DxNI6E78meodQI + wLsrKLeHn32iLvUqJbVDhfWSU
                WO4BAMcm1u02t4VKw++ttECPt + HUgPUq5pqQWe5Q2cW4TMsE
                = Y4Mw
                ---- - END PGP PUBLIC KEY BLOCK-----";
        public static int SRP_LEN_BYTES = 256;

        /// <summary>
        ///  Encode a byte array using BCrypt's slightly-modified base64 encoding scheme. Note that this
        ///  is *not* compatible with the standard MIME-base64 encoding.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
        ///                                     illegal values.</exception>
        /// <param name="byteArray">The byte array to encode.</param>
        /// <param name="length">   The number of bytes to encode.</param>
        /// <returns>Base64-encoded string.</returns>
        public static char[] EncodeBase64(byte[] byteArray, int length)
        {
            // Table for Base64 encoding
            char[] Base64Code = {
                '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
                '6', '7', '8', '9'
            };
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            int encodedSize = (int)Math.Ceiling((length * 4D) / 3);
            char[] encoded = new char[encodedSize];

            int pos = 0;
            int off = 0;
            while (off < length)
            {
                int c1 = byteArray[off++] & 0xff;
                encoded[pos++] = Base64Code[(c1 >> 2) & 0x3f];
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                int c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                encoded[pos++] = Base64Code[c2 & 0x3f];
            }

            return encoded;
        }

        //returns the last n elements of array
        public static byte[] TakeSuffix(byte[] array, int n)
        {
            byte[] answer = new byte[n];
            int j = 0;
            for (int i = 0; i < array.Length; i++)
            {
                int relativePosition = array.Length - i;
                if (relativePosition <= n)
                {
                    answer[j] = array[i];
                    j += 1;
                }
            }
            return answer;
        }

        //returns the first n elements of array
        public static byte[] TakePrefix(byte[] array, int n)
        {
            byte[] answer = new byte[n];
            for (int i = 0; i < array.Length; i++)
            {
                if (i < n)
                {
                    answer[i] = array[i];
                }
            }
            return answer;
        }

        /*
         * Convert a byte array to BigInteger. We need to specify the sign of the byte array by
         * appending the byte 0. See https://stackoverflow.com/questions/22053462/microsoft-biginteger-goes-negative-when-i-import-from-an-array
         * */
        public static BigInteger ByteToBigInteger(byte[] input)
        {
            Array.Resize(ref input, input.Length + 1);
            input[input.Length - 1] = 0;
            BigInteger output = new BigInteger(input);
            return output;
        }

        /*
         * return a new byte of length start.length + end.length
         * whose element are the elements of start followed by the elements of end
         * */
        public static byte[] Concat(byte[] start, byte[] end)
        {
            byte[] concatenatedByte = new byte[start.Length + end.Length];
            Array.Copy(start, 0, concatenatedByte, 0, start.Length);
            Array.Copy(end, 0, concatenatedByte, start.Length, end.Length);
            return concatenatedByte;
        }

        /*
         * Hash the input byte array by applying the sha512 algorithm
         */
        private static byte[] Digest(byte[] input)
        {
            byte[] input0 = Concat(input, new Byte[] { Convert.ToByte(0) });
            byte[] input1 = Concat(input, new Byte[] { Convert.ToByte(1) });
            byte[] input2 = Concat(input, new Byte[] { Convert.ToByte(2) });
            byte[] input3 = Concat(input, new Byte[] { Convert.ToByte(3) });
            SHA512 sha = new SHA512Managed();
            byte[] shaOutpu1 = sha.ComputeHash(input0);
            byte[] shaOutpu2 = sha.ComputeHash(input1);
            byte[] shaOutpu3 = sha.ComputeHash(input2);
            byte[] shaOutpu4 = sha.ComputeHash(input3);
            return Concat(Concat(shaOutpu1, shaOutpu2), Concat(shaOutpu3, shaOutpu4));
        }

        private static string ProtonSalt(byte[] salt)
        {
            //Compute the salt for the password hash
            byte[] protonBytes = Encoding.ASCII.GetBytes("proton");
            byte[] sShort = TakeSuffix(Concat(salt, protonBytes), 16);
            string s = Convert.ToBase64String(sShort);
            byte[] newSalt = Encoding.ASCII.GetBytes(s);
            byte[] bcrypt_base64 = Encoding.ASCII.GetBytes("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            byte[] std_base64chars = Encoding.ASCII.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
            Dictionary<byte, byte> translation = new Dictionary<byte, byte>();
            for (int i = 0; i < std_base64chars.Length; i++)
            {
                byte nextByte = std_base64chars[i];
                translation[nextByte] = bcrypt_base64[i];
            }
            byte[] newSalt2 = new byte[newSalt.Length];
            for (int i = 0; i < newSalt.Length; i++)
            {
                if (translation.ContainsKey(newSalt[i]))
                {
                    newSalt2[i] = translation[newSalt[i]];
                }
                else
                {
                    newSalt2[i] = newSalt[i];
                }
            }
            byte[] saltPrefix = Encoding.ASCII.GetBytes("$2y$10$");
            byte[] saltFinal = Concat(saltPrefix, newSalt2);
            return Encoding.ASCII.GetString(saltFinal);
        }

        //Computes the SRP proof
        public static SRP SRPCheck(string base64Modulus, byte[] server_challenge, int version, byte[] salt, string username, string password, string srpSession)
        {
            //compute N
            byte[] modulus = Convert.FromBase64String(base64Modulus);
            BigInteger N = ByteToBigInteger(modulus);
            //compute g
            byte[] g = new byte[Util.SRP_LEN_BYTES];
            g[0] = 2;
            BigInteger gBig = ByteToBigInteger(g);
            //compute k
            byte[] kLowerInputHash = Concat(g, modulus);
            byte[] k = Digest(kLowerInputHash);
            BigInteger kBig = ByteToBigInteger(k);
            //compute a and A
            Random rand = new Random();
            byte[] a = new byte[] { 52, 61, 160, 234, 67, 215, 153, 254, 181, 157, 4, 100, 16, 65, 87, 237, 83, 201, 88, 180, 226, 174, 161, 216, 63, 99, 153, 243, 82, 107, 20, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            //rand.NextBytes(a);
            BigInteger aBig = ByteToBigInteger(a);
            BigInteger A = BigInteger.ModPow(gBig, aBig, N);
            //compute u
            byte[] uLowerInputHash = Concat(A.ToByteArray(), server_challenge);
            byte[] u = Digest(uLowerInputHash);
            BigInteger uBig = ByteToBigInteger(u);
            if (version != 4 && version != 3)
            {
                return null;
            }
            // Hash the user's password
            string customSalt = ProtonSalt(salt);
            string passwordHash = HashPassword(password, customSalt);
            byte[] hashedPwdByte = Encoding.ASCII.GetBytes(passwordHash);
            // Compute x (private key)
            byte[] xLowerInputHash = Concat(hashedPwdByte, modulus);
            byte[] x = Digest(xLowerInputHash);
            BigInteger xBig = ByteToBigInteger(x);
            // Compute v
            BigInteger vBig = BigInteger.ModPow(gBig, xBig, N);
            // Compute S (K)
            BigInteger BBig = ByteToBigInteger(server_challenge);
            BigInteger sValue = BBig - (kBig * vBig);
            BigInteger sExponent = aBig + (uBig * xBig);
            BigInteger SBig = BigInteger.ModPow(sValue, sExponent, N);
            if (sValue.Sign == -1) // see https://stackoverflow.com/questions/74664517/c-sharp-gives-me-different-result-of-modpow-from-java-python-is-this-a-bug
            {
                SBig += N;
            }
            byte[] K = TakePrefix(SBig.ToByteArray(), Util.SRP_LEN_BYTES);
            // Compute M
            byte[] mUpperInputHash = Concat(Concat(A.ToByteArray(), server_challenge), K);
            byte[] M = Digest(mUpperInputHash);
            BigInteger KBig = ByteToBigInteger(K);
            // Compute expected server proof
            byte[] ESPInputHash = Concat(Concat(A.ToByteArray(), M), K);
            byte[] expectedServerProof = Digest(ESPInputHash);
            return new SRP(Convert.ToBase64String(A.ToByteArray()), Convert.ToBase64String(M), expectedServerProof);
        }

        public static byte[] EncryptStringToBytes_Aes(byte[] plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (RijndaelManaged aesAlg = new RijndaelManaged())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.Mode = CipherMode.CFB;
                aesAlg.FeedbackSize = 128;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainText, 0, plainText.Length);
                        csEncrypt.FlushFinalBlock();
                        encrypted = msEncrypt.ToArray();
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write("hello world !");
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;
            byte[] decrypted;
            // Create an Aes object
            // with the specified key and IV.
            using (RijndaelManaged aesAlg = new RijndaelManaged())
            {
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Mode = CipherMode.CFB;
                aesAlg.FeedbackSize = 128;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(cipherText, 0, cipherText.Length);
                        csDecrypt.FlushFinalBlock();
                        decrypted = msDecrypt.ToArray();
                        byte[] subArr1 = TakePrefix(decrypted, decrypted.Length - 3 - 20 - 2);
                        byte[] subArr2 = TakeSuffix(subArr1, subArr1.Length - 26);
                        string result = Encoding.UTF8.GetString(subArr2);
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                         //Read the decrypted bytes from the decrypting stream
                         //and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();

                        }
                    }
                }
            }

            return plaintext;
        }

        public static string ConvertByteUnits(int data)
        {
            if (data < 1000) return data.ToString() + " B";

            if (data < 1000000) return (data / 1000).ToString() + " KB";

            if (data < 1000000000) return (data / 1000000).ToString() + " MB";

            return (data / 1000000000).ToString() + " GB";
        }
    }
}