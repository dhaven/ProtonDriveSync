using KeePassLib.Utility;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Bcpg;
using PgpCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace ProtonSecrets.StorageProvider
{
    internal class ProtonAddress
    {
        public PGP privateKey;
        public string id;
        public string passphrase;

        public ProtonAddress(PGP privateKey, string id, string passphrase)
        {
            this.privateKey = privateKey;
            this.privateKey.HashAlgorithmTag = HashAlgorithmTag.Sha256;
            this.id = id;
            this.passphrase = passphrase;
        }

        public async static Task<ProtonAddress> Initialize(string email, PGP userPrivateKey, HttpClient client)
        {
            JObject addressInfo = null;
            try
            {
                HttpResponseMessage response = await client.GetAsync("https://api.protonmail.ch/addresses");
                //response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject bodyData = JObject.Parse(responseBody); ;
                addressInfo = bodyData;
            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                MessageService.ShowInfo(exception.Message);
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
            return new ProtonAddress(new PGP(adddressKeys_enc), addressID, decryptedToken);
        }
    }
}
