using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Bcpg;
using PgpCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace ProtonDriveSync.StorageProvider
{
    internal class ProtonAddress
    {
        public PGP privateKey;
        public string id;
        public string passphrase;
        public string email;

        public ProtonAddress(PGP privateKey, string id, string passphrase, string email)
        {
            this.privateKey = privateKey;
            this.privateKey.HashAlgorithmTag = HashAlgorithmTag.Sha256;
            this.id = id;
            this.passphrase = passphrase;
            this.email = email;
        }

        public async static Task<ProtonAddress> Initialize(string email, PGP userPrivateKey, ProtonAPI api)
        {
            JObject addressInfo;
            try
            {
                addressInfo = await api.ProtonRequest("GET", "https://api.protonmail.ch/addresses");
            }
            catch (Exception exception)
            {
                throw new Exception("Unable to intialize address info: " + exception.Message);
            }
            JArray addresses = (JArray)addressInfo["Addresses"];
            JArray keys = null;
            string addressID = "";
            for (int i = 0; i < addresses.Count(); i++)
            {
                if ((string)addresses[i]["Email"] == email)
                {
                    keys = (JArray)addresses[i]["Keys"];
                    addressID = (string)addresses[i]["ID"];
                }
            }
            string addressPrivateKey = "";
            string addressToken = "";
            for (int i = 0; i < keys.Count(); i++)
            {
                if ((int)keys[i]["Primary"] == 1)
                {
                    addressPrivateKey = (string)keys[i]["PrivateKey"];
                    addressToken = (string)keys[i]["Token"];
                }
            }
            string decryptedToken = await userPrivateKey.DecryptArmoredStringAsync(addressToken);
            EncryptionKeys adddressKeys_enc = new EncryptionKeys(addressPrivateKey, decryptedToken);
            return new ProtonAddress(new PGP(adddressKeys_enc), addressID, decryptedToken, email);
        }
    }
}
