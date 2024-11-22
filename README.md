![intro](https://github.com/user-attachments/assets/600f9e18-ebaa-4f54-9abb-192a87b1bd6e)

This is a walkthrough for the tryhackme CTF White Rose. I will not provide any flags or passwords as this is intended to be used as a guide. 

![intro2](https://github.com/user-attachments/assets/c97e5631-077f-44ca-b0f0-61df6ef48ff3)

## Scanning/Reconnaissance

First off, let's store the target IP as a variable for easy access.

Command: export ip=xx.xx.xx.xx

Next, let's run an nmap scan on the target IP:
```bash
nmap -sV -sC -A -v $ip -oN
```

Command break down:

-sV

Service Version Detection: This option enables version detection, which attempts to determine the version of the software running on open ports. For example, it might identify an HTTP server as Apache with a specific version.
-sC

Default Scripts: This option runs a collection of default NSE (Nmap Scripting Engine) scripts that are commonly useful. These scripts perform various functions like checking for vulnerabilities, gathering additional information, and identifying open services. They’re a good starting point for gathering basic information about a host.
-A

Aggressive Scan: This option enables several scans at once. It combines OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute (--traceroute). It’s useful for a comprehensive scan but can be intrusive and time-consuming.
-v

Verbose Mode: Enables verbose output, which provides more detailed information about the scan’s progress and results.
$ip

Target IP: This is a placeholder for the target IP address you want to scan. In practice, replace $ip with the actual IP of the machine you are targeting.
-oN

Output in Normal Format: This option saves the scan results in a plain text file format. After -oN, specify a filename where you want to store the output.

The scan reveals three open ports, ssh and a an ftp server on tcp/21 that allows anonymous login, and dns on tcp/53. Let's check out the ftp server.

Unfortunately, this turns up nothing:

![ftp](https://github.com/user-attachments/assets/cb216738-efc4-48ab-9733-bc1f9d528b5c)

After I was unable to find anything else, I ran a second nmap scan of all ports:

![nmap2](https://github.com/user-attachments/assets/5c8d411e-7ae9-4643-99fe-32c2e709dfb1)

Let's check out the web server on 1337.

![exposed](https://github.com/user-attachments/assets/c4605e23-54ab-4cb9-97c8-720e242a444f)

We come to a page that just says EXPOSED. Let's run a gobuster scan on this ip and port:

![buster1](https://github.com/user-attachments/assets/b48d39a1-8c67-496c-92c2-b53b97a377d3)

The beginning of the scan reveals an /admin dir:

![admin1](https://github.com/user-attachments/assets/b8e1ce7b-dcc0-4b8f-8e16-f451c2a5f21a)

However, this is a fake admin panel that doesn't do anything, so I let the gobuster scan continue... for a long time.

![admin_101](https://github.com/user-attachments/assets/d7986a33-27be-4c68-9d66-8b9485285c01)

Here is the real admin panel:

![admin_101](https://github.com/user-attachments/assets/99de7173-84c3-4f38-b169-95ddf9715c4d)

I tried many of the default like admin:admin, and admin:password and combos using the given email. So far everything just prompts this error message:

![admin2](https://github.com/user-attachments/assets/2c49b565-d340-435f-81df-5cad39129e5b)

When I tried a single quote ' in the user input, the popup displayed undefined:

![adminsql](https://github.com/user-attachments/assets/11c18c17-61ec-4149-9b65-b820b799ee31)

This is a clear sign that the login page is vulnerable to sql injection. We will capture a login request to this panel in burp suite and save it as request.txt:

![request txt](https://github.com/user-attachments/assets/55f02eea-ae9b-45fb-8ae2-8c1b8a2a06ab)

This the first sqlmap scan that I ran on requests.txt:

![sqlmap1](https://github.com/user-attachments/assets/054b84c5-9c7d-446c-898f-eff64452a2cf)

And this reveals, the database:expose, the table:user, two directories, a password, and a hash.

![sqlmap2](https://github.com/user-attachments/assets/67f2cea9-87f3-40a2-9107-17aa9964912b)

First I'm going to head to crackstation.net and crack that hash:

![crackstation net](https://github.com/user-attachments/assets/990f0503-2353-48ad-b5f1-a0814f23a4e1)

Now I'll head to the first directory where we are prompted for a password. The one I just cracked works:

![index php](https://github.com/user-attachments/assets/290f2951-e2f6-4cd2-bcc4-b50c0dfbc73b)

The index.php page, just reveals this message:

![index php2](https://github.com/user-attachments/assets/631e8b32-9d14-473a-af3f-9df2e58581a3)

If we check the source code, we can see this comment:

![hint](https://github.com/user-attachments/assets/d8fa9568-fc82-4063-9447-d2c1c00a0f2a)

I followed that hint and used .php?file=/etc/passwd and got the file.

![passwd](https://github.com/user-attachments/assets/29472006-2073-482f-9dfc-2fecce3f03ae)

Now, let's head to the upload directory:

![upload](https://github.com/user-attachments/assets/a372b95c-e733-4422-beba-06bb794d1a5e)

And we are prompted for a password, that is a machine user that starts with z. Looking at the /etc/passwd file, we see a zeamkish user, and this works.

And now we have a file upload page:

![upload2](https://github.com/user-attachments/assets/355608f7-b0f7-4cca-acf9-796cf439d98f)

Checking the source code shows that only jpg or png files are excepted. But, I think this is only on the client side. So, I will grab a php shell from revshells.com, change the extension to png, upload load it, but intercept the upload with burp, and switch the extension back to php:

![burp1](https://github.com/user-attachments/assets/b9c0decf-e451-41a7-a8f4-2d753b5360b7)

![burp2](https://github.com/user-attachments/assets/54cb775a-c2a7-433f-ab24-1c8a74576a5c)

Now, we just need to figure where the file has been uploaded to, so we can excute it.

![file uploaded](https://github.com/user-attachments/assets/fbbc8de0-466a-4c81-b86a-460f6fecc239)

![upload3](https://github.com/user-attachments/assets/4054cf86-f060-46e7-9433-0a97c5ef9556)

We can reveal the source code using lfi and the php filer
```bash
/file1010111/index.php?file=php://filter/convert.base64-encode/resource=../upload-cv00101011/index.php
```
This returns the base64 encoded source code:

![b64source](https://github.com/user-attachments/assets/d4a91166-9122-40f6-9076-9a786a5aeaa4)

![upload4](https://github.com/user-attachments/assets/fb638f0c-8f05-4948-8b06-b4be32ddaef8)

Now, clicking the php version, gives us the reverse shell.

