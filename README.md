# F*EX

F*EX (File EXchange) is a service to send big (large, huge, giant, ...) files
from sender user A to recipient user B by HTTP.

Sender and recipient user must have an e-mail-address and a web-browser, 
that is all (for them).

The sender uploads the file to the F*EX-server and the recipient
automatically gets a notification e-mail with a download-URL.

The sender must have a valid auth-ID, given by the F*EX administrator.

This F*EX distribution contains the F*EX server and the optional client 
programs fexsend, fexget, sexsend, sexget, xx and zz which run on UNIX. 

Simply run "./install", which installs all files into /home/fex/
Then edit /home/fex/lib/fex.ph and set your local config.

Afterwards you can add F*EX users with /home/fex/bin/fac

If you want to upgrade from a previous F*EX version, you also can run
"./install" which is save, because it will not overwrite:
  /home/fex/lib/fex.ph
  /home/fex/lib/fup.pl
  /home/fex/lib/reactivation.txt
  /home/fex/htdocs/index.html
but will create *_new versions of these files which you then can copy manually 
if you want.

See directory doc for more information.

Or fex some nice, funny, interesting videos (eg cute pets) to this address :-)


PS: I'm not the author of this wonderful software I just put it on github. ;)
