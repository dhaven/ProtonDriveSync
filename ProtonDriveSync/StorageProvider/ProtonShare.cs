using Newtonsoft.Json.Linq;
using PgpCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace ProtonDriveSync.StorageProvider
{
    internal class ProtonShare
    {
        public PGP privateKey;
        public string id;
        public string passphrase;
        public string linkID;
        public ProtonAddress owner;

        public ProtonShare(PGP privateKey, string id, string passphrase, string linkID, ProtonAddress owner)
        {
            this.privateKey = privateKey;
            this.id = id;
            this.passphrase = passphrase;
            this.linkID = linkID;
            this.owner = owner;
        }

        public static async Task<ProtonShare> Initialize(PGP userPrivateKey, ProtonAPI api)
        {
            JObject sharesInfo;
            try
            {
                sharesInfo = await api.ProtonRequest("GET", "https://api.protonmail.ch/drive/shares");
            }
            catch (Exception exception)
            {
                throw new Exception("unable to initialize shares info: " +  exception.Message);
            }
            JArray shares = (JArray)sharesInfo["Shares"];
            string shareId = "";
            for (int i = 0; i < shares.Count(); i++)
            {
                if ((int)shares[i]["Type"] == 1)
                {
                    shareId = (string)shares[i]["ShareID"];
                }
            }
            JObject shareInfo;
            try
            {
                shareInfo = await api.ProtonRequest("GET", "https://api.protonmail.ch/drive/shares/" + shareId);
            }
            catch (Exception exception)
            {
                throw new Exception ("unable to initialize specific share info: " + exception.Message);
            }
            string sharePrivateKey = (string)shareInfo["Key"];
            string sharePassphrase = (string)shareInfo["Passphrase"];
            string owner = (string)shareInfo["Creator"];

            //Initialize the address object
            ProtonAddress addressInfo = await ProtonAddress.Initialize(owner, userPrivateKey, api);

            //Decrypt sharePassphrase
            string decryptedPassphrase = await addressInfo.privateKey.DecryptArmoredStringAsync(sharePassphrase);
            EncryptionKeys shareKeys = new EncryptionKeys(sharePrivateKey, decryptedPassphrase);
            return new ProtonShare(new PGP(shareKeys), shareId, decryptedPassphrase, (string)shareInfo["LinkID"], addressInfo);
        }
    }
}
