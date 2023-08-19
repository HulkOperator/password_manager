# Password Manager
#### Video Demo: https://youtu.be/oiUIhfHBzCk
#### Description:
##### Summary
The project was done to meet the requirements of CS50's final project. This application is built using flask and jinja. This password manager can store all of your passwords at a single place.
By navigating to the register page, you can create an account. All of the passwords you create will be visible on the dashboard of your account and is private to you.
You can create new password entries by visiting the "Add New" page, which asks for information regarding the website, username, and password. By clicking the generate button, a random password of 18 characters is created by default. The length of this can be changed using the input field. Once the password is generated, you can save it.
The information regarding each entry is encrypted using AES-256. The password of your account is used to generate a key, which is used to encrypt/decrypt the local database. Hence, there is a strong password policy for your initial account on the application.
You can further edit previous entries or delete them. There is also an option to change your password. When the password changes, all the data belonging to your account is decrypted using your old password and ecrypted using the new password.

#### Implementation details:
The layout.html page was used to create a simple template design which is reused by the other html files.
##### Encryption
The schema for enc_data table consists of id, user_id, and data. "id" is the primary key for this table, and "user_id" indicates that this entry belongs to which user. This is a foreign key referenced to the user's table. The data column contains encrypted data for websites, usernames, and passwords. When a user logs in, an object for the class AESCipher is initialized with the user's password. While retrieving or adding data to the database, it is encrypted using a key derived from the user's password.

##### Index Page
This displays the dashboard for your account. All of your existing entries in the database is displayed here. On the existing entries, you can modify them or delete them. When you click either one of these, the id associated for this element in the database is sent to the /edit or /delete routes. However, before making any changes, verification is done if the current user has access to make the change. So, spoofing this id will throw an unauthorized 403 error.

##### Edit Page
When the "/edit" route is called, this checks for the id which needs to be modifed. All the entries for the current user is queried and this id is matched. Only if a match is found, the edits are made. Otherwise a 403 unauthorized error is called. The user can make changes to the website, username or password.

##### Delete Page
When the "/delete" route is called with an entry id, it is verified if it belongs to the current user. Once it is positive, the entire row is dropped.

##### Add new entry
While adding a new entry, the website, username, and password are required. Failure to provide all this information will lead to an error. The generate password button can be used to generate a random password string containing a mixture of uppercase, lowercase letters, numbers, and special characters.

##### Change Password
When requesting for a change of password, the existing password is confirmed and is replaced by the new password. All of the encrypted data is decrypted using the old key and encrypted using the new key.