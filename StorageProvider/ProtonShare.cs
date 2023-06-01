using KeePassLib.Utility;
using Newtonsoft.Json.Linq;
using PgpCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace ProtonSecrets.StorageProvider
{
    internal class ProtonShare
    {
        public PGP privateKey;
        public string id;
        public string passphrase;
        public string linkID;

        public ProtonShare(PGP privateKey, string id, string passphrase, string linkID)
        {
            this.privateKey = privateKey;
            this.id = id;
            this.passphrase = passphrase;
            this.linkID = linkID;
        }

        public static async Task<ProtonShare> Initialize(ProtonAddress addressInfo, HttpClient client)
        {
            JObject sharesInfo = null;
            try
            {
                HttpResponseMessage response = await client.GetAsync("https://api.protonmail.ch/drive/shares");
                //response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject bodyData = JObject.Parse(responseBody); ;
                sharesInfo = bodyData;
            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                MessageService.ShowInfo(exception.Message);
            }
            JArray shares = (JArray)sharesInfo["Shares"];
            string shareId = "";
            for (int i = 0; i < shares.Count(); i++)
            {
                if (shares[i]["CreationTime"].ToString() == "")
                {
                    shareId = (string)shares[i]["ShareID"];
                }
            }
            JObject shareInfo = null;
            try
            {
                HttpResponseMessage response = await client.GetAsync("https://api.protonmail.ch/drive/shares/" + shareId);
                //response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                JObject bodyData = JObject.Parse(responseBody); ;
                shareInfo = bodyData;
            }
            catch (HttpRequestException exception)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", exception.Message);
                MessageService.ShowInfo(exception.Message);
            }
            string sharePrivateKey = (string)shareInfo["Key"];
            string sharePassphrase = (string)shareInfo["Passphrase"];

            //Decrypt sharePassphrase
            string decryptedPassphrase = await addressInfo.privateKey.DecryptArmoredStringAsync(sharePassphrase);
            EncryptionKeys shareKeys = new EncryptionKeys(sharePrivateKey, decryptedPassphrase);
            return new ProtonShare(new PGP(shareKeys), shareId, decryptedPassphrase, (string)shareInfo["LinkID"]);
        }
    }
}
