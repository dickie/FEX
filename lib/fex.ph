# -*- perl -*- #

## your F*EX server host name (with domain)
$hostname = 'MYHOSTNAME.MYDOMAIN';

## admin email address used in notification emails
## to change it, you MUST call: fac -/ admin-email-address auth-id
$admin = 'fex@'.$hostname;

## server admin email address shown on web page
$ENV{SERVER_ADMIN} = $admin;

## restrict web administration to ip range(s)
@admin_hosts = qw(127.0.0.1 10.0.0.0-10.10.255.255);

## Bcc address for notification emails, must not be empty
$bcc = 'fex';

## send notifications about new F*EX releases (bugfixes!)
$notify_newrelease = $admin;

## optional: download-URLs sent in notification emails
# @durl = qw(
#   http://MYFEXSERVER/fop
#   https://MYFEXSERVER/fop
#   http://MYPROXY/fex/fop
# );

## On AUTO mode the fexserver sends notification emails automatically.
## On MANUAL mode the user must notify the recipients manually.
# $mailmode = 'MANUAL';
$mailmode = 'AUTO';

## optional: your mail domain
## if set it will be used as domain for every user without domain
## local_user ==> local_user@$mdomain
## if not set, addresses without domain produce an error
# $mdomain = 'MY.MAIL.DOMAIN';
# $admin = 'fexmaster@'.$mdomain;

## optional: static address (instead of F*EX user) in notification email From
## BEWARE: if set, mail error bounces will not go to the real sender, but
##         to this address!
# $sender_from = $admin;

## optional HTML header extra link and logo
# @H1_extra = qw(http://www.MY.ORG http://www.MY.ORG/logo.gif);

## disclaimer to be appended to every notification email
# $disclaimer = 'powered by camelcraft!';

## optional: suppress funny messages
# $boring = 1;

## optional: suppress warning messages about incompatible web browsers
# $nowarning = 'YES';

# locales to present (must be installed!)
# if empty, present all installed locales
# @locales = qw(english swabian);

## default locale: which languange is used in first place
# $default_locale = 'swabian';

## where to store the files and logs, must be writable for user fex!
# $spooldir = "$ENV{HOME}/spool";
# $logdir = $spooldir;

## default quota in MB for recipient; 0 means "no quota"
$recipient_quota = 0;

## default quota in MB for sender; 0 means "no quota"
$sender_quota = 0;

## expiration: keep files that number of days (default)
$keep = 5;

## expiration: keep files that number of days (maximum)
$keep_max = 99;

## autodelete: delete files after download (automatically)
##	YES     ==> immediatelly (1 minute grace time)
##	DELAY   ==> after download at next fex_cleanup cronjob run
##      2       ==> 2 days after download (can be any number!)
##	NO      ==> keep until expiration date (see $keep)
$autodelete = 'YES';

## purge: purge files after that number of days after their deletion
##        (purge deletes file meta-information)
$purge = '3*$keep';

## if the file has been already downloaded then subsequentials
## downloads are only allowed from the same client (uses cookies)
## to prevent unwanted file sharing
$limited_download = 'YES';

## allow RECIPIENT = SENDER
## in this case subsequentials downloads from any ip are possible until
## regular file expiration (KEEP); exception for $limited_download
$fex_yourself = 'YES';

## allow overwriting of files
$overwrite = 'YES';

## allow user requests for forgotten auth-IDs (then send by email)
$mail_authid = 'YES';

## optional: from which hosts and for which mail domains users may
##           register themselves as full users (must set both!)
# @local_hosts = qw(127.0.0.1 ::1 10.10.100.0-10.10.200.255 129.69.1.129);
# @local_domains = qw(uni-stuttgart.de flupp.org);
# @local_domains = qw(uni-stuttgart.de *.uni-stuttgart.de);

## optional: external users may register themselves as restricted users
##           for local receiving domains and hosts (must set both!)
# @local_rdomains = qw(flupp.org *.flupp.org);
# @local_rhosts = qw(10.0.0.0-10.0.255.255 129.69.1.129);
## optional: allow restricted user registration only by certain domains
# @registration_domains = qw(belwue.de ietf.org);
## optional: allow restricted user registration only by certain hosts
# @registration_hosts = qw(129.69.0.0-129.69.255.255 176.9.84.26);

## optional: for certain remote domains do not use sender address in
##           notfication email From, because their MTA will probably
##           reject it if From and To contain their domain name.
##           Instead use $admin for From. See also $sender_from
# @remote_domains = qw(flupp.org);

## optional: allow public upload via http://$hostname/pup for
# @public_recipients = qw(fexmaster@rus.uni-stuttgart.de);

## optional: allow anonymous upload without authentication for these IP ranges
# @anonymous_upload = qw(127.0.0.1 ::1 10.10.100.0-10.10.200.255 129.69.1.129);

## optional: mailing list addresses (allows multiple downloads)
# @mailing_lists = qw(admin@my.domain *@listserv*);

## optional: forbidden addresses
# @forbidden_recipients = qw(nobody@* postmaster@else.where);

## optional: forbidden ip addresses for CGIs
# @forbidden_hosts = qw(64.124.0.0-64.125.255.255);

# forbidden user agents (sucking "download manager", etc)
@forbidden_user_agents = qw(
  FDM
  Download.Master
  Java/[\d\.]+
);

## optional: restrict upload to these IP ranges
# @upload_hosts = qw(127.0.0.1 ::1 10.10.100.0-10.10.200.255 129.69.1.129);

## optional: restrict download to these address ranges
# @download_hosts = qw(127.0.0.1 10.10.100.0-10.10.200.255 129.69.1.129);

## optional: throttle bandwith for certain addresses (in kB/s)
##           0 means : full speed
##           first match wins
# @throttle = qw(
#	framstag@*:0 microsoft.com:100
#	127.0.0.1:0 202.0.0.0-211.255.255.255:1024
#	[::1]:0 [fe00::0-fe00::ffff]:0
# );

## optional: expire user accounts after x days of inactivity
##           delete=wipe out, notify=send mail to fex admin
# $account_expire = "100:delete";
# $account_expire = "365:notify";

## optional: allowed directories for file linking (see fexsend)
# @file_link_dirs = qw(/sw /nfs/home/exampleuser);

## optional: allow additional directories with static documents
##           $docdir (/home/fex/htdocs) is always allowed implicitly
# @doc_dirs = qw(/sw /nfs/home/exampleuser/htdocs);

## optional: text file with your conditions of using
##           will be append to registrations request replies
# $usage_conditions = "$docdir/usage_conditions.txt";

## optional: redirect URIs
##           URLs with leading ! are active http redirects
# %redirect = (
#   '/fstools/'   => '!http://fex.belwue.de/fstools/',
#   '/usecases/'  => 'http://fex.belwue.de/usecases/',
# );
