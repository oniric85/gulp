# Gulp! A Blind SQL Injection Exploiter

This is a small script I wrote to help investigating security vulnerabilities
in web applications. Code isn't perfect (quite hacked together if you ask me)
but it's quite functional and served me good when I was too lazy to find out how
to use similar tool in the wild and wrote one myself instead. It supports various
DBMS, most notably MySQL, and can exploit Blind SQL Injection by inspecting different
server responses. For completely blind SQL Injections Gulp! also support MySQL time-based
BENCHMARK attack. You can use Gulp! to dump every data you need, provided you know what
you are doing! Oh, and it's multithread too, just don't kill your target!

## Features
- Multithread
- Supports MySQL, Access, PostegreSQL, Oracle Database
- Blind SQL Injection exploitation
- Time-based SQL injection exploitation (MySQL only)

## Requirements

Bein a PERL script Gulp! requires Perl (of course). I recommend PERL >= 5.8, older
versions are not supported or tested. As usual there are also some dependencies to fulfill. Here the list of packages you will need. Just grab them from CPAN!

```perl
use HTTP::Request::Common;
use LWP::UserAgent;
use POSIX;
use Options;
use CGI::Enurl;
use URI;
```


## TODO
- automatic iteration through multiple rows
- time-based: dynamically changing the required time for TRUE and FALSE requests to balance changes in the server workload
- character range prediction ( maybe )
- config file support

## Known Issues/Behaviour
- Doesn't support HTTPS
- You can't specify empty POST parameters.
- You can't use the characters "&" or "=" in your request content ( query parameter ) if you use POST method, you must urlencode them FIRST.
- When redirecting the received Set-Cookie header is used to set a Cookie header