#  -*- perl -*-

use 5.008;
use utf8;
use Fcntl 		qw':flock :seek :mode';
use IO::Handle;
use IPC::Open3;
use Encode;
use Digest::MD5 	qw'md5_hex';
use File::Basename;
use Sys::Hostname;
use Symbol		qw'gensym';

# set and untaint ENV if not in CLI (fexsrv provides clean ENV)
unless (-t) {
  foreach my $v (keys %ENV) {
    ($ENV{$v}) = ($ENV{$v} =~ /(.*)/s) if defined $ENV{$v};
  }
  $ENV{PATH}     = '/usr/local/bin:/bin:/usr/bin';
  $ENV{IFS}      = " \t\n";
  $ENV{BASH_ENV} = '';
}

unless ($FEXLIB = $ENV{FEXLIB} and -d $FEXLIB) {
  die "$0: found no FEXLIB - fexsrv needs full path\n"
}

$FEXLIB =~ s:/+:/:g;
$FEXLIB =~ s:/$::;

# $FEXHOME is top-level directory of F*EX installation or vhost
# $ENV{HOME} is login-directory of user fex
# in default-installation both are equal, but they may differ
$FEXHOME = $ENV{FEXHOME} or $ENV{FEXHOME} = $FEXHOME = dirname($FEXLIB);

umask 077;

# defaults
$hostname = gethostname();
$tmpdir = $ENV{TMPDIR} || '/var/tmp';
$spooldir = $FEXHOME.'/spool';
$docdir = $FEXHOME.'/htdocs';
$logdir = $spooldir;
$autodelete = 'YES';
$overwrite = 'YES';
$limited_download = 'YES';	# multiple downloads only from same client
$fex_yourself = 'YES';	        # allow SENDER = RECIPIENT
$keep = 5;	    		# days
$recipient_quota = 0; 		# MB
$sender_quota = 0;    		# MB
$timeout = 30;	 		# seconds
$bs = 2**16;		 	# I/O blocksize
$DS = 60*60*24;			# seconds in a day
$MB = 1024*1024;		# binary Mega
$use_cookies = 1;
$sendmail = '/usr/lib/sendmail';
$sendmail = '/usr/sbin/sendmail' unless -x $sendmail;
$mailmode = 'auto';
$bcc = 'fex';
$default_locale = '';
$fop_auth = 0;
$mail_authid = 'yes';
$force_https = 0;
$debug = 0;
@forbidden_user_agents = ('FDM');

# https://securityheaders.io/
# https://scotthelme.co.uk/hardening-your-http-response-headers/
# http://content-security-policy.com/
@extra_header = (
  # "Content-Security-Policy: sandbox allow-forms allow-scripts",
  "Content-Security-Policy: script-src 'self' 'unsafe-inline'",
  "X-Frame-Options: SAMEORIGIN",
  "X-XSS-Protection: 1; mode=block",
  "X-Content-Type-Options: nosniff",
);

$FHS = -f '/etc/fex/fex.ph' and -d '/usr/share/fex/lib';
# Debian FHS
if ($FHS) {
  $ENV{FEXHOME} = $FEXHOME = '/usr/share/fex';
  $spooldir = '/var/spool/fex';
  $logdir = '/var/log/fex';
  $docdir = '/var/lib/fex/htdocs';
  $notify_newrelease = '';
}

# allowed download managers (HTTP User-Agent)
$adlm = '^(Axel|fex)';

# local config
require "$FEXLIB/fex.ph" or die "$0: cannot load $FEXLIB/fex.ph - $!";

$fop_auth	= 0 if $fop_auth	=~ /no/i;
$mail_authid	= 0 if $mail_authid	=~ /no/i;
$force_https	= 0 if $force_https	=~ /no/i;
$debug		= 0 if $debug		=~ /no/i;

@logdir = ($logdir) unless @logdir;
$logdir = $logdir[0];

# allowed multi download recipients: from any ip, any times
if (@mailing_lists) {
  $amdl = '^('.join('|',map { quotewild($_) } @mailing_lists).')$';
} else {
  $amdl = '^-$';
}

# check for name based virtual host
$vhost = vhost($ENV{'HTTP_HOST'});

$RB = 0; # read POST bytes

push @doc_dirs,$docdir;
foreach my $ld (glob "$FEXHOME/locale/*/htdocs") {
  push @doc_dirs,$ld;
}

$nomail = ($mailmode =~ /^MANUAL|nomail$/i);

if (not $nomail and not -x $sendmail) {
  http_die("found no sendmail");
}
http_die("cannot determine the server hostname") unless $hostname;

$ENV{PROTO} = 'http' unless $ENV{PROTO};
$keep = $keep_default ||= $keep || 5;
$purge ||= 3*$keep;
$fra = $ENV{REMOTE_ADDR} || '';
$sid = $ENV{SID} || '';

$dkeydir = "$spooldir/.dkeys"; # download keys
$ukeydir = "$spooldir/.ukeys"; # upload keys
$akeydir = "$spooldir/.akeys"; # authentification keys
$skeydir = "$spooldir/.skeys"; # subuser authentification keys
$gkeydir = "$spooldir/.gkeys"; # group authentification keys
$xkeydir = "$spooldir/.xkeys"; # extra download keys
$lockdir = "$spooldir/.locks"; # download lock files

if (my $ra = $ENV{REMOTE_ADDR} and $max_fail) {
  mkdirp("$spooldir/.fail");
  $faillog = "$spooldir/.fail/$ra";
}

unless ($admin) {
  $admin = $ENV{SERVER_ADMIN} ? $ENV{SERVER_ADMIN} : 'fex@'.$hostname;
}

# $ENV{SERVER_ADMIN} may be set empty in fex.ph!
$ENV{SERVER_ADMIN} = $admin unless defined $ENV{SERVER_ADMIN};

$mdomain ||= '';

if ($use_cookies) {
  if (my $cookie = $ENV{HTTP_COOKIE}) {
    if    ($cookie =~ /\bakey=(\w+)/) { $akey = $1 }
    # elsif ($cookie =~ /\bskey=(\w+)/) { $skey = $1 }
  }
}

if (@locales) {
  if ($default_locale and not grep /^$default_locale$/,@locales) {
    push @locales,$default_locale;
  }
  if (@locales == 1) {
    $default_locale = $locales[0];
  }
}

$default_locale ||= 'english';

# $durl is first default fop download URL
# @durl is optional mandatory fop download URL list (from fex.ph)
unless ($durl) {
  my $host = '';
  my $port = 80;
  my $xinetd = '/etc/xinetd.d/fex';

  if (@durl) {
    $durl = $durl[0];
  } elsif ($ENV{HTTP_HOST} and $ENV{PROTO}) {

    ($host,$port) = split(':',$ENV{HTTP_HOST}||'');
    $host = $hostname;

    unless ($port) {
      $port = 80;
      if (open $xinetd,$xinetd) {
        while (<$xinetd>) {
          if (/^\s*port\s*=\s*(\d+)/) {
            $port = $1;
            last;
          }
        }
        close $xinetd;
      }
    }

    # use same protocal as uploader for download
    if ($ENV{PROTO} eq 'https' and $port == 443 or $port == 80) {
      $durl = "$ENV{PROTO}://$host/fop";
    } else {
      $durl = "$ENV{PROTO}://$host:$port/fop";
    }
  } else {
    if (open $xinetd,$xinetd) {
      while (<$xinetd>) {
        if (/^\s*port\s*=\s*(\d+)/) {
          $port = $1;
          last;
        }
      }
      close $xinetd;
    }
    if ($port == 80) {
      $durl = "http://$hostname/fop";
    } else {
      $durl = "http://$hostname:$port/fop";
    }
  }
}
@durl = ($durl) unless @durl;


sub reexec {
  exec($FEXHOME.'/bin/fexsrv') if $ENV{KEEP_ALIVE};
  exit;
}


sub jsredirect {
  $url = shift;
  $cont = shift || 'request accepted: continue';

  http_header('200 ok');
  print html_header($head||$ENV{SERVER_NAME});
  pq(qq(
    '<script type="text/javascript">'
    '  window.location.replace("$url");'
    '</script>'
    '<noscript>'
    '  <h3><a href="$url">$cont</a></h3>'
    '</noscript>'
    '</body></html>'
  ));
  &reexec;
}


sub debug {
  print header(),"<pre>\n";
  print "file = $file\n";
  foreach $v (keys %ENV) {
    print $v,' = "',$ENV{$v},"\"\n";
  }
  print "</pre><p>\n";
}


sub nvt_print {
  foreach (@_) { syswrite STDOUT,"$_\r\n" }
}


sub html_quote {
  local $_ = shift;

  s/&/&amp;/g;
  s/</&lt;/g;
  s/\"/&quot;/g;

  return $_;
}



sub http_header {

  my $status = shift;
  my $msg = $status;

  return if $HTTP_HEADER;
  $HTTP_HEADER = $status;

  $msg =~ s/^\d+\s*//;

  nvt_print("HTTP/1.1 $status");
  nvt_print("X-Message: $msg");
  # nvt_print("X-SID: $ENV{SID}") if $ENV{SID};
  nvt_print("Server: fexsrv");
  nvt_print("Expires: 0");
  nvt_print("Cache-Control: no-cache");
  if ($force_https) {
    # https://www.owasp.org/index.php/HTTP_Strict_Transport_Security
    # https://scotthelme.co.uk/hsts-the-missing-link-in-tls/
    nvt_print("Strict-Transport-Security: max-age=2851200; preload");
  }
  nvt_print($_) foreach(@extra_header);
  if ($use_cookies) {
    $akey = md5_hex("$from:$id") if $id and $from;
    if ($akey) {
      nvt_print("Set-Cookie: akey=$akey; path=/; Max-Age=9999; Discard");
    }
    # if ($skey) {
    #   nvt_print("Set-Cookie: skey=$skey; Max-Age=9999; Discard");
    # }
    if ($locale) {
      nvt_print("Set-Cookie: locale=$locale");
    }
  }
  unless (grep /^Content-Type:/i,@_) {
    # nvt_print("Content-Type: text/html; charset=ISO-8859-1");
    nvt_print("Content-Type: text/html; charset=UTF-8");
  }

  nvt_print(@_,'');
}


sub html_header {
  my $title = shift;
  my $header = 'header.html';
  my $head;

  binmode(STDOUT,':utf8'); # for text/html !

  # http://www.w3.org/TR/html401/struct/global.html
  # http://www.w3.org/International/O-charset
  $head = qqq(qq(
    '<html>'
    '<head>'
    '  <meta http-equiv="expires" content="0">'
    '  <meta http-equiv="Content-Type" content="text/html;charset=utf-8">'
    '  <title>$title</title>'
    '</head>'
  ));
  # '<!-- <style type="text/css">\@import "/fex.css";</style> -->'

  if ($0 =~ /fexdev/) { $head .= "<body bgcolor=\"pink\">\n" }
  else                { $head .= "<body>\n" }

  $title =~ s:F\*EX:<a href="/index.html">F*EX</a>:;

  if (open $header,'<',"$docdir/$header") {
    $head .= $_ while <$header>;
    close $header;
  }

  $head .= &$prolog($title) if defined($prolog);

  if (@H1_extra) {
    $head .= sprintf(
      '<h1><a href="%s"><img align=center src="%s" border=0></a>%s</h1>',
      $H1_extra[0],$H1_extra[1]||'',$title
    );
  } else {
    $head .= "<h1>$title</h1>";
  }
  $head .= "\n";

  return $head;
}


sub html_error {
  my $error = shift;
  my $msg = "@_";
  my @msg = @_;
  my $isodate = isodate(time);

  $msg =~ s/[\s\n]+/ /g;
  $msg =~ s/<.+?>//g; # remove HTML
  map { s/<script.*?>//gi } @msg;

  errorlog($msg);

  $SIG{ALRM} = sub {
    $SIG{__DIE__} = 'DEFAULT';
    die "TIMEOUT\n";
  };
  alarm($timeout);

  # cannot send standard HTTP Status-Code 400, because stupid
  # Internet Explorer then refuses to display HTML body!
  http_header("666 Bad Request - $msg");
  print html_header($error);
  print 'ERROR: ',join("<p>\n",@msg),"\n";
  pq(qq(
    '<p><hr><p>'
    '<address>
    '  $ENV{HTTP_HOST}'
    '  $isodate'
    '  <a href="mailto:$ENV{SERVER_ADMIN}">$ENV{SERVER_ADMIN}</a>'
    '</address>'
    '</body></html>'
  ));
  exit;
}


sub http_die {

  # not in CGI mode
  unless ($ENV{GATEWAY_INTERFACE}) {
    warn "$0: @_\n"; # must not die, because of fex_cleanup!
    return;
  }

  debuglog(@_);

  # create special error file on upload
  if ($uid) {
    my $ukey = "$spooldir/.ukeys/$uid";
    $ukey .= "/error" if -d $ukey;
    unlink $ukey;
    if (open $ukey,'>',$ukey) {
      print {$ukey} join("\n",@_),"\n";
      close $ukey;
    }
  }

  html_error($error||'',@_);
}


sub check_maint {
  if (my $status = readlink '@MAINTENANCE') {
    my $isodate = isodate(time);
    http_header('666 MAINTENANCE');
    print html_header($head||'');
    pq(qq(
      "<center>"
      "<h1>Server is in maintenance mode</h1>"
      "<h3>($status)</h3>"
      "</center>"
      "<p><hr><p>"
      "<address>$ENV{HTTP_HOST} $isodate</address>"
      "</body></html>"
    ));
    exit;
  }
}


sub check_status {
  my $user = shift;

  $user = lc $user;
  $user .= '@'.$mdomain if $mdomain and $user !~ /@/;

  if (-e "$user/\@DISABLED") {
    my $isodate = isodate(time);
    http_header('666 DISABLED');
    print html_header($head);
    pq(qq(
      "<h3>$user is disabled</h3>"
      "Contact $ENV{SERVER_ADMIN} for details"
      "<p><hr><p>"
      "<address>$ENV{HTTP_HOST} $isodate</address>"
      "</body></html>"
    ));
    exit;
  }
}


sub isodate {
  my @d = localtime shift;
  return sprintf('%d-%02d-%02d %02d:%02d:%02d',
                 $d[5]+1900,$d[4]+1,$d[3],$d[2],$d[1],$d[0]);
}


sub encode_Q {
  my $s = shift;
  $s =~ s{([\=\x00-\x20\x7F-\xA0])}{sprintf("=%02X",ord($1))}eog;
  return $s;
}


# from MIME::Base64::Perl
sub decode_b64 {
  local $_ = shift;
  my $uu = '';
  my ($i,$l);

  tr|A-Za-z0-9+=/||cd;
  s/=+$//;
  tr|A-Za-z0-9+/| -_|;
  return '' unless length;
  $l = (length)-60;
  for ($i = 0; $i <= $l; $i += 60) {
    $uu .= "M" . substr($_,$i,60);
  }
  $_ = substr($_,$i);
  $uu .= chr(32+(length)*3/4) . $_ if $_;
  return unpack ("u",$uu);
}


# short base64 encoding
sub b64 {
  local $_ = '';
  my $x = 0;

  pos($_[0]) = 0;
  $_ = join '',map(pack('u',$_)=~ /^.(\S*)/, ($_[0]=~/(.{1,45})/gs));
  tr|` -_|AA-Za-z0-9+/|;
  $x = (3 - length($_[0]) % 3) % 3;
  s/.{$x}$//;

  return $_;
}


# simulate a "rm -rf", but never removes '..'
# return number of removed files
sub rmrf {
  my @files = @_;
  my $dels = 0;
  my ($file,$dir);
  local *D;
  local $_;

  foreach (@files) {
    next if /(^|\/)\.\.$/;
    /(.*)/; $file = $1;
    if (-d $file and not -l $file) {
      $dir = $file;
      opendir D,$dir or next;
      while ($file = readdir D) {
        next if $file eq '.' or $file eq '..';
        $dels += rmrf("$dir/$file");
      }
      closedir D;
      rmdir $dir and $dels++;
    } else {
      unlink $file and $dels++;
    }
  }
  return $dels;
}


sub gethostname {
  my $hostname = hostname;
  my $domain;
  local $_;

  unless ($hostname) {
    $_ = `hostname 2>/dev/null`;
    $hostname = /(.+)/ ? $1 : '';
  }
  if ($hostname !~ /\./ and open my $rc,'/etc/resolv.conf') {
    while (<$rc>) {
      if (/^\s*domain\s+([\w.-]+)/) {
        $domain = $1;
        last;
      }
      if (/^\s*search\s+([\w.-]+)/) {
        $domain = $1;
      }
    }
    close $rc;
    $hostname .= ".$domain" if $domain;
  }
  if ($hostname !~ /\./ and $admin and $admin =~ /\@([\w.-]+)/) {
    $hostname .= '.'.$1;
  }

  return $hostname;
}


# strip off path names (Windows or UNIX)
sub strip_path {
  local $_ = shift;

  s/.*\\// if /^([A-Z]:)?\\/;
  s:.*/::;

  return $_;
}


# substitute all critcal chars
sub normalize {
  local $_ = shift;

  return '' unless defined $_;

  # we need perl native utf8 (see perldoc utf8)
  $_ = decode_utf8($_) unless utf8::is_utf8($_);

  s/[\r\n\t]+/ /g;
  s/[\x00-\x1F\x80-\x9F]/_/g;
  s/^\s+//;
  s/\s+$//;

  return encode_utf8($_);
}


# substitute all critcal chars
sub normalize_html {
  local $_ = shift;

  return '' unless defined $_;

  $_ = normalize($_);
  s/[\"<>]//g;

  return $_;
}



# substitute all critcal chars with underscore
sub normalize_filename {
  local $_ = shift;

  return $_ unless $_;

  # we need native utf8
  $_ = decode_utf8($_) unless utf8::is_utf8($_);

  $_ = strip_path($_);

  # substitute all critcal chars with underscore
  s/[^a-zA-Z0-9_=.+-]/_/g;
  s/^\./_/;

  return encode_utf8($_);
}


sub normalize_email {
  local $_ = lc shift;

  s/[^\w_.+=!~#^\@\-]//g;
  s/^\./_/;
  /(.*)/;
  return $1;
}


sub normalize_user {
  my $user = shift;

  $user = lc(urldecode(despace($user)));
  $user .= '@'.$mdomain if $mdomain and $user !~ /@/;
  checkaddress($user) or http_die("$user is not a valid e-mail address");
  return untaint($user);
}


sub urldecode {
  local $_ = shift;
  s/%([a-f0-9]{2})/chr(hex($1))/gie;
  return $_;
}


sub untaint {
  local $_ = shift;
  /(.*)/s;
  return $1;
}


sub checkchars {
  my $input = shift;
  local $_ = shift;

  if (/^([|+.])/) {
    http_die("\"$1\" is not allowed at beginning of $input");
  }
  if (/([\/\"\'\\<>;])/) {
    http_die(sprintf("\"&#%s;\" is not allowed in %s",ord($1),$input));
  }
  if (/(\|)$/) {
    http_die("\"$1\" is not allowed at end of $input");
  }
  if (/[\000-\037]/) {
    http_die("control characters are not allowed in $input");
  }
  /(.*)/;
  return $1;
}


sub checkaddress {
  my $a = shift;
  my $re;
  local $_;
  local ($domain,$dns);

  $a =~ s/:\w+=.*//; # remove options from address

  return $a if $a eq 'anonymous';

  $a .= '@'.$mdomain if $mdomain and $a !~ /@/;

  $re = '^[.@-]|@.*@|local(host|domain)$|["\'\`\|\s()<>/;,]';
  if ($a =~ /$re/i) {
    debuglog("$a has illegal syntax ($re)");
    return '';
  }
  $re = '^[!^=~#_:.+*{}\w\-\[\]]+\@(\w[.\w\-]*\.[a-z]+)$';
  if ($a =~ /$re/i) {
    $domain = $dns = $1;
    {
      local $SIG{__DIE__} = sub { die "\n" };
      eval q{
        use Net::DNS;
        $dns = Net::DNS::Resolver->new->query($domain)||mx($domain);
        unless ($dns or mx('uni-stuttgart.de')) {
          http_die("Internal error: bad resolver");
        }
      }
    };
    if ($dns) {
      return untaint($a);
    } else {
      debuglog("no A or MX DNS record found for $domain");
      return '';
    }
  } else {
    debuglog("$a does not match e-mail regexp ($re)");
    return '';
  }
}


# check forbidden addresses
sub checkforbidden {
  my $a = shift;
  my ($fr,$pr);
  local $_;

  $a .= '@'.$mdomain if $mdomain and $a !~ /@/;
  return $a if -d "$spooldir/$a"; # ok, if user already exists
  if (@forbidden_recipients) {
    foreach (@forbidden_recipients) {
      $fr = quotewild($_);
      # skip public recipients
      if (@public_recipients) {
        foreach $pr (@public_recipients) {
          return $a if $a eq lc $pr;
        }
      }
      return '' if $a =~ /^$fr$/i;
    }
  }
  return $a;
}


sub randstring {
  my $n = shift;
  my @rc = ('A'..'Z','a'..'z',0..9 );
  my $rn = @rc;
  my $rs;

  for (1..$n) { $rs .= $rc[int(rand($rn))] };
  return $rs;
}


# emulate mkdir -p
sub mkdirp {
  my $dir = shift;
  my $pdir;

  return if -d $dir;
  $dir =~ s:/+$::;
  http_die("cannot mkdir /") unless $dir;
  $pdir = $dir;
  if ($pdir =~ s:/[^/]+$::) {
    mkdirp($pdir) unless -d $pdir;
  }
  unless (-d $dir) {
    mkdir $dir,0770 or http_die("mkdir $dir - $!");
  }
}


# hash with SID
sub sidhash {
  my ($rid,$id) = @_;

  if ($rid and $ENV{SID} and $id =~ /^MD5H:/) {
    $rid = 'MD5H:'.md5_hex($rid.$ENV{SID});
  }
  return $rid;
}


# test if ip is in iplist (ipv4/ipv6)
# iplist is an array with ips and ip-ranges
sub ipin {
  my ($ip,@list) = @_;
  my ($i,$ia,$ib);

  $ipe = lc(ipe($ip));
  map { lc } @list;

  foreach $i (@list) {
    if ($ip =~ /\./ and $i =~ /\./ or $ip =~ /:/ and $i =~ /:/) {
      if ($i =~ /(.+)-(.+)/) {
        ($ia,$ib) = ($1,$2);
        $ia = ipe($ia);
        $ib = ipe($ib);
        return $ip if $ipe ge $ia and $ipe le $ib;
      } else {
        return $ip if $ipe eq ipe($i);
      }
    }
  }
  return '';
}

# ip expand (ipv4/ipv6)
sub ipe {
  local $_ = shift;

  if (/^\d+\.\d+\.\d+\.\d+$/) {
    s/\b(\d\d?)\b/sprintf "%03d",$1/ge;
  } elsif (/^[:\w]+:\w+$/) {
    s/\b(\w+)\b/sprintf "%04s",$1/ge;
    s/^:/0000:/;
    while (s/::/::0000:/) { last if length > 39 }
    s/::/:/;
  } else {
    $_ = '';
  }
  return $_;
}


sub filename {
  my $file = shift;
  my $filename;

  if (open $file,'<',"$file/filename") {
    $filename = <$file>||'';
    chomp $filename;
    close $file;
  }

  unless ($filename) {
    $filename = $file;
    $filename =~ s:.*/::;
  }

  return $filename;
}


sub urlencode {
  local $_ = shift;
  s/(^[.~]|[^\w.,=:~^+-])/sprintf "%%%X",ord($1)/ge;
  return $_;
}


# file and document log
sub fdlog {
  my ($log,$file,$s,$size) = @_;
  my $ra = $ENV{REMOTE_ADDR}||'-';
  my $msg;

  $ra .= '/'.$ENV{HTTP_X_FORWARDED_FOR} if $ENV{HTTP_X_FORWARDED_FOR};
  $ra =~ s/\s//g;
  $file =~ s:/data$::;
  $msg = sprintf "%s [%s_%s] %s %s %s/%s\n",
         isodate(time),$$,$ENV{REQUESTCOUNT},$ra,encode_Q($file),$s,$size;

  writelog($log,$msg);
}


# extra debug log
sub debuglog {
  my $prg = $0;
  local $_;

  return unless $debug and @_;
  unless ($debuglog and fileno $debuglog) {
    my $ddir = "$spooldir/.debug";
    mkdir $ddir,0770 unless -d $ddir;
    $prg =~ s:.*/::;
    $prg = untaint($prg);
    $debuglog = sprintf("%s/%s_%s_%s.%s",
                        $ddir,time,$$,$ENV{REQUESTCOUNT}||0,$prg);
    $debuglog =~ s/\s/_/g;
    # http://perldoc.perl.org/perlunifaq.html#What-is-a-%22wide-character%22%3f
    # open $debuglog,'>>:encoding(UTF-8)',$debuglog or return;
    open $debuglog,'>>',$debuglog or return;
    # binmode($debuglog,":utf8");
    autoflush $debuglog 1;
    # printf {$debuglog} "\n### %s ###\n",isodate(time);
  }
  while ($_ = shift @_) {
    $_ = encode_utf8($_) if utf8::is_utf8($_);
    s/\n*$/\n/;
    s/<.+?>//g; # remove HTML
    print {$debuglog} $_;
    print "DEBUG: $_" if -t;
  }
}


# extra debug log
sub errorlog {
  my $prg = $0;
  my $msg = "@_";
  my $ra = $ENV{REMOTE_ADDR}||'-';

  $ra .= '/'.$ENV{HTTP_X_FORWARDED_FOR} if $ENV{HTTP_X_FORWARDED_FOR};
  $ra =~ s/\s//g;
  $prg =~ s:.*/::;
  $msg =~ s/[\r\n]+$//;
  $msg =~ s/[\r\n]+/ /;
  $msg =~ s/\s*<p>.*//;
  $msg = sprintf "%s %s %s %s\n",isodate(time),$prg,$ra,$msg;

  writelog('error.log',$msg);
}


sub writelog {
  my $log = shift;
  my $msg = shift;

  foreach my $logdir (@logdir) {
    if (open $log,'>>',"$logdir/$log") {
      flock $log,LOCK_EX;
      seek $log,0,SEEK_END;
      print {$log} $msg;
      close $log;
    }
  }
}


# failed authentification log
sub faillog {
  my $request = shift;
  my $n = 1;

  if ($faillog and $max_fail_handler and open $faillog,"+>>$faillog") {
    flock($faillog,LOCK_EX);
    seek $faillog,0,SEEK_SET;
    $n++ while <$faillog>;
    printf {$faillog} "%s %s\n",isodate(time),$request;
    close $faillog;
    &$max_fail_handler($ENV{REMOTE_ADDR}) if $n > $max_fail;
  }
}

# remove all white space
sub despace {
  local $_ = shift;
  s/\s//g;
  return $_;
}


# superquoting
sub qqq {
  local $_ = shift;
  my ($s,$i,@s);
  my $q = "[\'\"]"; # quote delimiter chars " and '

  # remove first newline and look for default indention
  s/^((\d+)?)?\n//;
  $i = ' ' x ($2||0);

  # remove trailing spaces at end
  s/[ \t]*?$//;

  @s = split "\n";

  # first line have a quote delimiter char?
  if (/^\s+$q/) {
    # remove heading spaces and delimiter chars
    foreach (@s) {
      s/^\s*$q//;
      s/$q\s*$//;
    }
  } else {
    # find the line with the fewest heading spaces (and count them)
    # (beware of tabs!)
    $s = length;
    foreach (@s) {
      if (/^( *)\S/ and length($1) < $s) { $s = length($1) };
    }
    # adjust indention
    foreach (@s) {
      s/^ {$s}/$i/;
    }
  }

  return join("\n",@s)."\n";
}


# print superquoted
sub pq {
  my $H = STDOUT;

  if (@_ > 1 and defined fileno $_[0]) { $H = shift }
  binmode($H,':utf8');
  print {$H} qqq(@_);
}


# check sender quota
sub check_sender_quota {
  my $sender = shift;
  my $squota = $sender_quota||0;
  my $du = 0;
  my ($file,$size,%file,$data,$upload);
  local $_;

  if (open $qf,'<',"$sender/\@QUOTA") {
    while (<$qf>) {
      s/#.*//;
      $squota = $1 if /sender.*?(\d+)/i;
    }
    close $qf;
  }

  foreach $file (glob "*/$sender/*") {
    $data = "$file/data";
    $upload = "$file/upload";
    if (not -l $data and $size = -s $data) {
      # count hard links only once (= same inode)
      my $i = (stat($data))[1]||0;
      unless ($file{$i}) {
        $du += $size;
        $file{$i} = $i;
      }
    } elsif (-f $upload) {
      # count hard links only once (= same inode)
      my $i = (stat($upload))[1]||0;
      unless ($file{$i}) {
        $size = readlink "$file/size" and $du += $size;
        $file{$i} = $i;
      }
    }
  }

  return($squota,int($du/1024/1024));
}


# check recipient quota
sub check_recipient_quota {
  my $recipient = shift;
  my $rquota = $recipient_quota||0;
  my $du = 0;
  my ($file,$size);
  local $_;

  if (open my $qf,'<',"$recipient/\@QUOTA") {
    while (<$qf>) {
      s/#.*//;
      $rquota = $1 if /recipient.*?(\d+)/i;
    }
    close $qf;
  }

  foreach $file (glob "$recipient/*/*") {
    if (-f "$file/upload" and $size = readlink "$file/size") {
      $du += $size;
    } elsif (not -l "$file/data" and $size = -s "$file/data") {
      $du += $size;
    }
  }

  return($rquota,int($du/1024/1024));
}


sub getline {
  my $file = shift;
  local $_;
  chomp($_ = <$file>||'');
  return $_;
}


# (shell) wildcard matching
sub wcmatch {
  local $_ = shift;
  my $p = quotemeta shift;

  $p =~ s/\\\*/.*/g;
  $p =~ s/\\\?/./g;
  $p =~ s/\\\[/[/g;
  $p =~ s/\\\]/]/g;

  return /$p/;
}


sub logout {
  my $logout;
  if    ($skey) { $logout = "/fup?logout=skey:$skey" }
  elsif ($gkey) { $logout = "/fup?logout=gkey:$gkey" }
  elsif ($akey) { $logout = "/fup?logout=akey:$akey" }
  else          { $logout = "/fup?logout" }
  return qqq(qq(
    '<p>'
    '<form name="logout" action="$logout">'
    '  <input type="submit" name="logout" value="logout">'
    '</form>'
    '<p>'
  ));
}


# print data dump of global or local variables in HTML
# input musst be a string, eg: '%ENV'
sub DD {
  my $v = shift;
  local $_;

  $n =~ s/.//;
  $_ = eval(qq(use Data::Dumper;Data::Dumper->Dump([\\$v])));
  s/\$VAR1/$v/;
  s/&/&amp;/g;
  s/</&lt;/g;
  print "<pre>\n$_\n</pre>\n";
}

# make symlink
sub mksymlink {
  my ($file,$link) = @_;
  unlink $file;
  return symlink untaint($link),$file;
}


# copy file (and modify) or symlink
# returns chomped file contents or link name
# preserves permissions and time stamps
sub copy {
  my ($from,$to,$mod) = @_;
  my $link;
  local $/;
  local $_;

  $to .= '/'.basename($from) if -d $to;

  if (defined($link = readlink $from)) {
    mksymlink($to,$link);
    return $link;
  } else {
    open $from,'<',$from or return;
    open $to,'>',$to or return;
    $_ = <$from>;
    close $from;
    eval $mod if $mod;
    print {$to} $_;
    close $to or http_die("internal error: $to - $!");
    if (my @s = stat($from)) {
      chmod $s[2],$to;
      utime @s[8,9],$to unless $mod;
    }
    chomp;
    return $_;
  }
}


sub slurp {
  my $file = shift;
  local $_;
  local $/;

  if (open $file,$file) {
    $_ = <$file>;
    close $file;
  }

  return $_;
}


# read one line from STDIN (net socket) and assign it to $_
# return number of read bytes
# also set global variable $RB (read bytes)
sub nvt_read {
  my $len = 0;

  if (defined ($_ = <STDIN>)) {
    debuglog($_);
    $len = length;
    $RB += $len;
    s/\r?\n//;
  }
  return $len;
}


# read forward to given pattern
sub nvt_skip_to {
  my $pattern = shift;

  while (&nvt_read) { return if /$pattern/ }
}


# HTTP GET and POST parameters
# (not used by fup)
# fills global variable %PARAM :
# normal parameter is $PARAM{$parameter}
# file parameter is $PARAM{$parameter}{filename} $PARAM{$parameter}{data}
sub parse_parameters {
  my $cl = $ENV{X_CONTENT_LENGTH} || $ENV{CONTENT_LENGTH} || 0;
  my $data = '';
  my $filename;
  local $_;

  if ($cl > 128*$MB) {
    http_die("request too large");
  }

  binmode(STDIN,':raw');

  foreach (split('&',$ENV{QUERY_STRING})) {
    if (/(.+?)=(.*)/) { $PARAM{$1} = $2 }
    else              { $PARAM{$_} = $_ }
  }
  $_ = $ENV{CONTENT_TYPE}||'';
  if ($ENV{REQUEST_METHOD} eq 'POST' and /boundary=\"?([\w\-\+\/_]+)/) {
    my $boundary = $1;
    while ($RB<$cl and &nvt_read) { last if /^--\Q$boundary/ }
    # continuation lines are not checked!
    while ($RB<$cl and &nvt_read) {
      $filename = '';
      if (/^Content-Disposition:.*\s*filename="(.+?)"/i) {
        $filename = $1;
      }
      if (/^Content-Disposition:\s*form-data;\s*name="(.+?)"/i) {
        my $p = $1;
        # skip rest of mime part header
        while ($RB<$cl and &nvt_read) { last if /^\s*$/ }
        $data = '';
        while (<STDIN>) {
          if ($p =~ /password/i) {
            debuglog('*' x length)
          } else {
            debuglog($_)
          }
          $RB += length;
          last if /^--\Q$boundary/;
          $data .= $_;
        }
        unless (defined $_) { die "premature end of HTTP POST\n" }
        $data =~ s/\r?\n$//;
        if ($filename) {
          $PARAM{$p}{filename} = $filename;
          $PARAM{$p}{data} = $data;
        } else {
          $PARAM{$p} = $data;
        }
        last if /^--\Q$boundary--/;
      }
    }
  }
}


# name based virtual host?
sub vhost {
  my $hh = shift; # HTTP_HOST
  my $vhost;
  my $locale = $ENV{LOCALE};

  # memorized vhost? (default is in fex.ph)
  %vhost = split(':',$ENV{VHOST}) if $ENV{VHOST};

  if (%vhost and $hh and $hh =~ s/^([\w\.-]+).*/$1/) {
    if ($vhost = $vhost{$hh} and -f "$vhost/lib/fex.ph") {
      $ENV{VHOST} = "$hh:$vhost"; # memorize vhost for next run
      $ENV{FEXLIB} = $FEXLIB = "$vhost/lib";
      $logdir = $spooldir    = "$vhost/spool";
      $docdir                = "$vhost/htdocs";
      @logdir = ($logdir);
      if ($locale and -e "$vhost/locale/$locale/lib/fex.ph") {
        $ENV{FEXLIB} = $FEXLIB = "$vhost/locale/$locale/lib";
      }
      require "$FEXLIB/fex.ph" or die "$0: cannot load $FEXLIB/fex.ph - $!";
      $ENV{SERVER_NAME} = $hostname;
      @doc_dirs = ($docdir);
      foreach my $ld (glob "$FEXHOME/locale/*/htdocs") {
        push @doc_dirs,$ld;
      }
      return $vhost;
    }
  }
}


sub gpg_encrypt {
  my ($plain,$to,$keyring,$from) = @_;
  my ($pid,$pi,$po,$pe,$enc,$err);
  local $_;

  $pe = gensym;

  $pid = open3($po,$pi,$pe,
    "gpg --batch --trust-model always --keyring $keyring".
    "    -a -e -r $bcc -r $to"
  ) or return;

  print {$po} "\n",$plain,"\n";
  close $po;

  $enc .= $_ while <$pi>;
  $err .= $_ while <$pe>;
  errorlog("($from --> $to) $err") if $err;

  close $pi;
  close $pe;
  waitpid($pid,0);

  return $enc;
}


sub mtime {
  my @s = stat(shift) or return;
  return $s[9];
}


# wildcard * to perl regexp
sub quotewild {
  local $_ = quotemeta shift;
  s/\\\*/.*/g; # allow wildcard *
  return $_;
}


# extract locale functions into hash of subroutine references
# e.g. \&german ==> $notify{german}
sub locale_functions {
  my $locale = shift;
  local $/;
  local $_;

  if ($locale and open my $fexpp,"$FEXHOME/locale/$locale/lib/fex.pp") {
    $_ = <$fexpp>;
    s/.*\n(\#\#\# locale functions)/$1/s;
    # sub xx {} ==> xx{$locale} = sub {}
    s/\nsub (\w+)/\n\$$1\{$locale\} = sub/gs;
    s/\n}\n/\n};\n/gs;
    eval $_;
    close $fexpp;
  }
}

sub notify_locale {
  my $dkey = shift;
  my $status = shift || 'new';
  my ($to,$keep,$locale,$file,$filename,$comment,$autodelete,$replyto,$mtime);
  local $_;

  if ($dkey =~ m:/.+/.+/:) {
    $file = $dkey;
    $dkey = readlink("$file/dkey");
  } else {
    $file = readlink("$dkeydir/$dkey")
      or http_die("internal error: no DKEY $DKEY");
  }
  $file =~ s:^../::;
  $filename = filename($file);
  $to = $file;
  $to =~ s:/.*::;
  $mtime = mtime("$file/data") or http_die("internal error: no $file/data");
  $comment = slurp("$file/comment") || '';
  $replyto = readlink "$file/replyto" || '';
  $autodelete = readlink "$file/autodelete"
             || readlink "$to/\@AUTODELETE"
             || $::autodelete;
  $keep = readlink "$file/keep"
       || readlink "$to/\@KEEP"
       || $keep_default;

  $locale = readlink "$to/\@LOCALE" || readlink "$file/locale" || 'english';
  $_ = untaint("$FEXHOME/locale/$locale/lib/lf.pl");
  require if -f;
  unless ($notify{$locale}) {
    $locale = 'english';
    $notify{$locale} ||= \&notify;
  }
  return &{$notify{$locale}}(
    status     => $status,
    dkey       => $dkey,
    filename   => $filename,
    keep       => $keep-int((time-$mtime)/$DS),
    comment    => $comment,
    autodelete => $autodelete,
    replyto    => $replyto,
  );
}

########################### locale functions ###########################
# Will be extracted by install process and saved in $FEXHOME/lib/lf.pl #
# You cannot modify them here without re-installing!                   #
########################################################################

# locale function!
sub notify {
  # my ($status,$dkey,$filename,$keep,$warn,$comment,$autodelete) = @_;
  my %P = @_;
  my ($to,$from,$file,$mimefilename,$receiver,$warn,$comment,$autodelete);
  my ($size,$bytes,$days,$header,$data,$replyto,$uurl);
  my ($mfrom,$mto,$dfrom,$dto);
  my $proto = 'http';
  my $durl = $::durl;
  my $index;
  my $fileid = 0;
  my $fua = $ENV{HTTP_USER_AGENT}||'';
  my $warning = '';
  my $disclaimer = '';
  my $download = '';
  my $keyring;
  my $boundary = randstring(16);
  my ($body,$enc_body);

  return if $nomail;

  $warn = $P{warn}||2;
  $comment = $P{comment}||'';
  $comment = encode_utf8($P{comment}||'') if utf8::is_utf8($comment);
  $comment =~ s/^!\*!//; # multi download allow flag
  $autodelete = $P{autodelete}||$::autodelete;

  $file = untaint(readlink("$dkeydir/$P{dkey}"));
  $file =~ s/^\.\.\///;
  # make download protocal same as upload protocol
  if ($uurl = readlink("$file/uurl") and $uurl =~ /^(\w+):/) {
    $proto = $1;
    $durl =~ s/^\w+::/$proto::/;
  }
  $index = "$proto://$hostname/index.html";
  ($to,$from,$file) = split('/',$file);
  $filename = strip_path($P{filename});
  $mfrom = $from;
  $mto = $to;
  $mfrom .= '@'.$mdomain if $mdomain and $mfrom !~ /@/;
  $mto .=   '@'.$mdomain if $mdomain and $mto   !~ /@/;
  $keyring = $to.'/@GPG';
  # $to = '' if $to eq $from; # ???
  $replyto = $P{replyto}||$mfrom;
  $header = "From: <$mfrom> ($mfrom via F*EX service $hostname)\n";
  $header .= "Reply-To: <$replyto>\n" if $replyto ne $mfrom;
  $header .= "To: <$mto>\n";
  $data = "$dkeydir/$P{dkey}/data";
  $size = $bytes = -s $data;
  return unless $size;
  $warning =
    "We recommend fexget or fexit for download,\n".
    "because these clients can resume the download after an interruption.\n".
    "See $proto://$hostname/tools.html";
  # if ($nowarning) {
  #   $warning = '';
  # } else {
  #   $warning =
  #     "Please avoid download with Internet Explorer, ".
  #     "because it has too many bugs.\n\n";
  # }
  if ($filename =~ /\.(tar|zip|7z|arj|rar)$/) {
    $warning .= "\n\n".
      "$filename is a container file.\n".
      "You can unpack it for example with 7zip ".
      "(http://www.7-zip.org/download.html)";
  }
  if ($limited_download =~ /^y/i) {
    $warning .= "\n\n".
      'This download link only works for you, you cannot distribute it.';
  }
  if ($size < 2048) {
    $size = "$size Bytes";
  } elsif ($size/1024 < 2048) {
    $size = int($size/1024)." kB";
  } else {
    $size = int($size/1024/1024)." MB";
  }
  if ($autodelete eq 'YES') {
    $autodelete = "WARNING: After download (or view with a web browser!), "
                . "the file will be deleted!";
  } elsif ($autodelete eq 'DELAY') {
    $autodelete = "WARNING: When you download the file it will be deleted "
                . "soon afterwards!";
  } else {
    $autodelete = '';
  }

  if (-s $keyring) {
    $mimefilename = '';
  } else {
    $mimefilename = $filename;
    if ($mimefilename =~ s/([_\?\=\x00-\x1F\x7F-\xFF])/sprintf("=%02X",ord($1))/eog) {
      $mimefilename =~ s/ /_/g;
      $mimefilename = '=?UTF-8?Q?'.$mimefilename.'?=';
    }
  }

  unless ($fileid = readlink("$dkeydir/$P{dkey}/id")) {
    my @s = stat($data);
    $fileid =  @s ? $s[1].$s[9] : 0;
  }

  if ($P{status} eq 'new') {
    $days = $P{keep};
    $header .= "Subject: F*EX-upload: $mimefilename\n";
  } else {
    $days = $warn;
    $header .= "Subject: reminder F*EX-upload: $mimefilename\n";
  }
  $header .= "X-FEX-Client-Address: $fra\n" if $fra;
  $header .= "X-FEX-Client-Agent: $fua\n"   if $fua;
  foreach my $u (@durl?@durl:($durl)) {
    my $durl = sprintf("%s/%s/%s",$u,$P{dkey},normalize_filename($filename));
    $header .= "X-FEX-URL: $durl\n" unless -s $keyring;
    $download .= "$durl\n";
  }
  $header .=
    "X-FEX-Filesize: $bytes\n".
    "X-FEX-File-ID: $fileid\n".
    "X-FEX-Fexmaster: $ENV{SERVER_ADMIN}\n".
    "X-Mailer: F*EX\n".
    "MIME-Version: 1.0\n";
  if ($comment =~ s/^\[(\@(.*?))\]\s*//) {
    $receiver = "group $1";
    if ($_ = readlink "$from/\@GROUP/$2" and m:^../../(.+?)/:) {
      $receiver .= " (maintainer: $1)";
    }
  } else {
    $receiver = 'you';
  }
  if ($days == 1) { $days .= " day" }
  else            { $days .= " days" }

  # explicite sender set in fex.ph?
  if ($sender_from) {
    map { s/^From: <$mfrom/From: <$sender_from/ } $header;
    open $sendmail,'|-',$sendmail,$mto,$bcc
      or http_die("cannot start sendmail - $!");
  } else {
    # for special remote domains do not use same domain in From,
    # because remote MTA will probably reject this e-mail
    $dfrom = $1 if $mfrom =~ /@(.+)/;
    $dto   = $1 if $mto   =~ /@(.+)/;
    if ($dfrom and $dto and @remote_domains and
        grep {
          $dfrom =~ /(^|\.)$_$/ and $dto =~ /(^|\.)$_$/
        } @remote_domains)
    {
      $header =~ s/(From: <)\Q$mfrom\E(.*?)\n/$1$admin$2\nReply-To: $mfrom\n/;
      open $sendmail,'|-',$sendmail,$mto,$bcc
        or http_die("cannot start sendmail - $!");
    } else {
      open $sendmail,'|-',$sendmail,'-f',$mfrom,$mto,$bcc
        or http_die("cannot start sendmail - $!");
    }
  }
  $comment = "\n$comment\n" if $comment;
  if ($comment =~ s/\n!(shortmail|\.)!\s*//i
    or (readlink("$to/\@NOTIFICATION")||'') =~ /short/i
  ) {
    $body = qqq(qq(
      '$comment'
      '$download'
      '$size'
    ));
  } else {
    $disclaimer = slurp("$from/\@DISCLAIMER") || qqq(qq(
      '$warning'
      ''
      'F*EX is not an archive, it is a transfer system for personal files.'
      'For more information see $index'
      ''
      'Questions? ==> F*EX admin: $admin'
    ));
    $disclaimer .= "\n$::disclaimer\n" if $::disclaimer;
    $body = qqq(qq(
      '$comment'
      '$from has uploaded the file'
      '  "$filename"'
      '($size) for $receiver. Use'
      ''
      '$download'
      'to download this file within $days.'
      ''
      '$autodelete'
      ''
      '$disclaimer'
    ));
  }
  $body =~ s/\n\n+/\n\n/g;
  if (-s $keyring) {
    $enc_body = gpg_encrypt($body,$to,$keyring,$from);
  }
  if ($enc_body) {
    # RFC3156
    $header .= qqq(qq(
      'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";'
      '\tboundary="$boundary"'
      'Content-Disposition: inline'
    ));
    $body = qqq(qq(
      '--$boundary'
      'Content-Type: application/pgp-encrypted'
      'Content-Disposition: attachment'
      ''
      'Version: 1'
      ''
      '--$boundary'
      'Content-Type: application/octet-stream'
      'Content-Disposition: inline; filename="fex.pgp"'
      ''
      '$enc_body'
      '--$boundary--'
    ));
  } else {
    $header .=
      "Content-Type: text/plain; charset=UTF-8\n".
      "Content-Transfer-Encoding: 8bit\n";
  }
  print {$sendmail} $header,"\n",$body;
  close $sendmail and return $to;
  http_die("cannot send notification e-mail (sendmail error $!)");
}


# locale function!
sub reactivation {
  my ($expire,$user) = @_;
  my $fexsend = "$FEXHOME/bin/fexsend";
  my $reactivation = "$FEXLIB/reactivation.txt";

  return if $nomail;

  if (-x $fexsend) {
    if ($locale) {
      my $lr = "$FEXHOME/locale/$locale/lib/reactivation.txt";
      $reactivation = $lr if -f $lr and -s $lr;
    }
    $fexsend .= " -M -D -k 30 -C"
               ." 'Your F*EX account has been inactive for $expire days,"
               ." you must download this file to reactivate it."
               ." Otherwise your account will be deleted.'"
               ." $reactivation $user";
    # on error show STDOUT and STDERR
    my $fo = `$fexsend 2>&1`;
    warn $fexsend.'\n'.$fo if $?;
  } else {
    warn "$0: cannot execute $fexsend for reactivation()\n";
  }
}

1;
