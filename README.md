# ProtonPass
ProtonPass is a plugin for the password manager app [KeePass](https://keepass.info/index.html). With KeePass passwords are kept in an encrypted database called a KDBX file. ProtonPass provides a solution for accessing KDBX files stored on [ProtonDrive](https://proton.me/drive/free) which is an end-to-end encrypted service. ProtonDrive provides a higher level of security  compared to well known Cloud storage solutions such as Dropbox or Google Drive.

## Requirements
- A KeePass installation
- A Proton account

## Setup

1. Download the latest version of the plugin from the [release page](https://github.com/dhaven/protonPass/releases). Unzip it and put the folder in the Plugins folder of your KeePass installation.
2. **Connect to Proton**: In order to be able to read/write files in ProtonDrive, ProtonPass needs access to your Proton account. Go to _Tools -> ProtonPass Settings..._ and enter your username and password. If you have 2fa enabled you will also be asked to enter the 6 digit code.

## Open/Save database

Once the initial setup has been completed you should be able to access KDBX files stored in ProtonDrive. If you don't have any KDBX file in ProtonDrive you should first upload one. You can do so either by using the ProtonDrive web app or from KeePass directly by saving your currently opened database to ProtonDrive. To do this :
1. Open the database you wish to add to ProtonDrive.
2. Go to _File -> Save As -> Save to ProtonDrive..._
3. Choose a folder location and filename and click OK.

Once you have a KDBX file in ProtonDrive you can open it in KeePass with the following steps:
1. Go to _File -> Open -> Open from ProtonDrive..._
2. Choose the folder where your KDBX file is located and select the file then click OK.
3. Enter your master password to unlock your database

## Technical FAQ

- **Does ProtonPass downloads the KDBX file to local storage so that KeePass can open it?** Your KDBX file is never written to disk. Instead it is streamed directly to the appllication and kept in memory until the application closes.
- **Does ProtonPass caches my password?** Not exactly. ProtonPass caches a transformed version of the password called a keyPassword as well as an access key and refresh token. This data is stored inside Windows credential manager. You can delete it at any time by going to _Tools -> ProtonPass settings..._ and clicking on the logout button. If you do so ProtonPass will no longer be able to access your KDBX files in that account.

## Acknowledgements

This plugin is heavily inspired by the project [KeeAnywhere](https://github.com/Kyrodan/KeeAnywhere/tree/master/KeeAnywhere) which povides similar functionalities as ProtonPass but for other Cloud Storage solution.
