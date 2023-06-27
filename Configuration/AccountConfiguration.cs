namespace ProtonSecrets.Configuration
{
    public class AccountConfiguration
    {
        public string KeyPassword { get; set; }

        public string Email { get; set; }

        public string UID { get; set; }

        public string AccessToken { get; set; }

        public string RefreshToken { get; set; }

        public bool Is2faEnabled { get; set; }

        public AccountConfiguration(string KeyPassword, string Email, string UID, string AccessToken, string RefreshToken, bool Is2faEnabled)
        {
            this.KeyPassword = KeyPassword;
            this.Email = Email;
            this.UID = UID;
            this.AccessToken = AccessToken;
            this.Is2faEnabled = Is2faEnabled;
            this.RefreshToken = RefreshToken;
        }
    }
}