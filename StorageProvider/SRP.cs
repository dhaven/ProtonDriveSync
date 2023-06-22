using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using PgpCore;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Numerics;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.StartPanel;
using static BCrypt.Net.BCrypt;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TextBox;
using System.Collections;

namespace ProtonSecrets.StorageProvider
{
    public class SRP
    {

        public async static Task<Dictionary<string,string>> GetSrp(JObject authInfo, string username, string password)
        {
            // Verify signed  message
            EncryptionKeys encryptionKeys = new EncryptionKeys(Util.SRP_MODULUS_KEY);
            PGP pgp = new PGP(encryptionKeys);
            VerificationResult result = await pgp.VerifyAndReadClearArmoredStringAsync((string)authInfo["Modulus"]);
            if(!result.IsVerified)
            {
                throw new Exception("could not verify the modulus");
            }
            //get other info from response
            int version = int.Parse((string)authInfo["Version"]);
            byte[] serverEphemeral = Convert.FromBase64String((string)authInfo["ServerEphemeral"]);
            byte[] salt = Convert.FromBase64String((string)authInfo["Salt"]);
            // Hash the user's password
            string customSalt = Util.ProtonSalt(salt);
            string passwordHash = HashPassword(password, customSalt);
            Dictionary<string, byte[]>  proofs = GenerateProofs(Convert.FromBase64String(result.ClearText), passwordHash, serverEphemeral);
            return new Dictionary<string,string>()
            {
                {"clientEphemeral", Convert.ToBase64String(proofs["clientEphemeral"]) },
                {"clientProof", Convert.ToBase64String(proofs["clientProof"]) },
                {"expectedServerProof", Convert.ToBase64String(proofs["expectedServerProof"]) }
            };
        }

        public static Dictionary<string, byte[]>  GenerateProofs(byte[] modulus, string hashedPassword, byte[] serverEphemeral)
        {
            //initialize generator
            byte[] generator = new byte[Util.SRP_LEN_BYTES];
            generator[0] = 2;
            //compute multiplier
            byte[] multiplier = Util.Digest(Util.Concat(generator, modulus));
            BigInteger multiplierBn = Util.ByteToBigInteger(multiplier);
            BigInteger BN_0 = new BigInteger(0);
            BigInteger BN_1 = new BigInteger(1);
            BigInteger BN_2 = new BigInteger(2);
            BigInteger modulusMinusOne = Util.ByteToBigInteger(modulus) - BN_1;
            if (BigInteger.Compare(multiplierBn, BN_1) <= 0 || BigInteger.Compare(multiplierBn, modulusMinusOne) >= 0)
            {
                throw new Exception("SRP multiplier is out of bounds");
            }
            if (BigInteger.Compare(Util.ByteToBigInteger(generator), BN_1) <= 0 || BigInteger.Compare(Util.ByteToBigInteger(generator), modulusMinusOne) >= 0)
            {
                throw new Exception("SRP generator is out of bounds");
            }
            if (BigInteger.Compare(Util.ByteToBigInteger(serverEphemeral), BN_1) <= 0 || BigInteger.Compare(Util.ByteToBigInteger(serverEphemeral), modulusMinusOne) >= 0)
            {
                throw new Exception("SRP server ephemeral is out of bounds");
            }
            Dictionary<string, byte[]> parameters = GetParameters(generator, modulus, serverEphemeral);

            // Compute the shared session in 3 steps
            // 1. Compute the base
            // 2. Compute the exponent
            // 3. Compute base^exponent mod modulus
            // hardcode values for testing
            byte[] x = Util.Digest(Util.Concat(Encoding.ASCII.GetBytes(hashedPassword), modulus));
            BigInteger vBn = BigInteger.ModPow(Util.ByteToBigInteger(generator), Util.ByteToBigInteger(x), Util.ByteToBigInteger(modulus));
            BigInteger baseBn = Util.ByteToBigInteger(serverEphemeral) - ((multiplierBn * vBn) % Util.ByteToBigInteger(modulus));
            BigInteger remainder = new BigInteger();
            BigInteger exponentBn = BigInteger.DivRem(Util.ByteToBigInteger(parameters["clientSecret"]) + (Util.ByteToBigInteger(parameters["scramblingParam"]) * Util.ByteToBigInteger(x)), modulusMinusOne, out remainder);
            if (baseBn.Sign == -1) // see https://stackoverflow.com/questions/74664517/c-sharp-gives-me-different-result-of-modpow-from-java-python-is-this-a-bug
            {
                baseBn += Util.ByteToBigInteger(modulus);
            }
            BigInteger sharedSessionBn = BigInteger.ModPow(baseBn, remainder, Util.ByteToBigInteger(modulus));
            //compute client proof
            byte[] sharedSession = Util.TakePrefix(sharedSessionBn.ToByteArray(), Util.SRP_LEN_BYTES);
            byte[] clientProof = Util.Digest(Util.Concat(Util.Concat(parameters["clientEphemeral"], serverEphemeral), sharedSession));
            //compute expected server proof
            byte[] expectedServerProof = Util.Digest(Util.Concat(Util.Concat(parameters["clientEphemeral"], clientProof), sharedSession));
            return new Dictionary<string, byte[]>()
            {
                {"clientEphemeral", parameters["clientEphemeral"] },
                {"clientProof", clientProof },
                {"expectedServerProof", expectedServerProof },
                {"sharedSession", sharedSession }
            };
        }

        public static Dictionary<string, byte[]> GetParameters(byte[] generator, byte[] modulus, byte[] serverEphemeral)
        {
            Random rand = new Random();
            byte[] clientSecret = new byte[256];
            rand.NextBytes(clientSecret);
            BigInteger clientEphemeral = BigInteger.ModPow(Util.ByteToBigInteger(generator), Util.ByteToBigInteger(clientSecret), Util.ByteToBigInteger(modulus));
            byte[] scramblingParam = Util.Digest(Util.Concat(Util.TakePrefix(clientEphemeral.ToByteArray(),Util.SRP_LEN_BYTES), serverEphemeral));
            return new Dictionary<string, byte[]>()
            {
                {"clientSecret", clientSecret},
                {"clientEphemeral", Util.TakePrefix(clientEphemeral.ToByteArray(),Util.SRP_LEN_BYTES) },
                {"scramblingParam", scramblingParam }
            };
        }
    }
}