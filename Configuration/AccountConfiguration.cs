namespace ProtonSecrets.Configuration
{
    public class AccountConfiguration
    {
        public string KeyPassword { get; set; }

        public string Email { get; set; }

        public string UID { get; set; }

        public string AccessToken { get; set; }

        public AccountConfiguration(string KeyPassword, string Email, string UID, string AccessToken)
        {
            this.KeyPassword = KeyPassword;
            this.Email = Email;
            this.UID = UID;
            this.AccessToken = AccessToken;
        }
    }
}