package FAQ;

my ($faq,$var,$env,$q,$a,$c,$s,$t,$n);
my (@faq,%Q,%A,@s);
my @sections = qw'Meta User Admin Misc';

@faq = ($faq) = $ENV{PATH_INFO} =~ /(\w+).html/;
@faq = map {lc} @sections if $faq eq 'all';

print "<style type=text/css><!-- h2,h3 {font-weight:normal} --></style>\n";

print '<h1><a name="top" href="/index.html">F*EX</a> ';
printf "Frequently Asked Questions: %s</h1>\n",ucfirst($faq);

if ($faq ne 'local') {
  print "<h3>Sections: ";
  foreach $s (@sections,'All') {
    if ($s =~ /$faq/i) {
      print "<b>$s</b>\n";
    } else {
      printf "[<a href=\"%s.html\">%s</a>]\n",lc($s),$s;
    }
  }
  print "</h3>\n";
}

print "<p><hr><p>\n";
print "<table>\n";

foreach my $faq (@faq) {
  open $faq,"$faq.faq" or next;
  local $/ = "Q:";
  local $_ = <$faq>;
  while (<$faq>) {
    chomp;
    while (/\$([\w_]+)\$/) {
      $var = $1;
      $env = $ENV{$var} || '';
      # s/\$$var\$/<code>$env<\/code>/g;
      s/\$$var\$/$env/g;
    };
    ($q,$a) = split /A:\s*/;
    $q =~ s/[\s\n]+$//;
    $q =~ s/^\s+//;
    $q =~ s! (/\w[\S]+/[\S]+)! <code>$1</code>!g;
    $a =~ s/[\s\n]+$/\n/;
    $a =~ s/^\s+//;
    while ($a =~ s/^(\s*)\*/$1<ul>\n$1<li>/m) {
      while ($a =~ s/(<li>.*\n\s*)\*/$1<li>/g) {}
      $a =~ s:(.*\n)(\s*)(<li>[^\n]+\n):$1$2$3$2</ul>\n:s
    }
    $a =~ s/\n\n/\n<p>\n/g;
    $a =~ s/([^>\n\\])\n/$1<br>\n/g;
    $a =~ s/<pre>(.+?)<\/pre>/pre($1)/ges;
    $a =~ s/\\\n/\n/g;
#    $a =~ s/^\s*<br>\s*//mg;
    $a =~ s/<([^\s<>\@]+\@[\w.-]+)>/<a href="mailto:$1">&lt;$1><\/a>/g;
    $a =~ s! (/\w[\S]+/[\S]+)! <code>$1</code>!g;
    $a =~ s!(https?://[\w-]+\.[^\s<>()]+)!<a href="$1">[$1]</a>!g or
    $a =~ s!(https?://[^\s<>()]+)!<code>$1</code></a>!g;
    push @{$Q{$faq}},$q;
    push @{$A{$faq}},$a;
  }
  close $faq;
}

print "<table>\n";

foreach $s (sections($faq)) {

  $c = lc $s;
  $s = '' if $s eq 'Local';
  $t = '';
  $t = $s if $faq eq 'all';

  for ($n = 0; $n < scalar(@{$Q{$c}}); $n++) {
    $q = ${Q{$c}[$n]};
    $qa = anchor($q);
    printf '<tr valign=top><th align=left>'.
           '<a href="#%s%d" style="text-decoration: none">'.
           '<font color="black">%s&nbsp;Q%d</a>:'.
           '<td><a href="#%s">%s</a></tr>'."\n",
           $t,$n+1,$s,$n+1,$qa,$q;
  }
}

print "</table>\n";
print "<p><hr><p>\n";

foreach $s (sections($faq)) {

  $c = lc $s;
  $s = '' if $s eq 'Local';
  $t = '';
  $t = $s if $faq eq 'all';

  for ($n = 0; $n < scalar(@{$Q{$c}}); $n++) {
    $q = ${Q{$c}[$n]};
    $qa = anchor($q);
    print "<p>\n";
    print "<table>\n";
    printf "<tr valign=top><th>".
           "<a name=\"%s%d\">%s&nbsp;Q%d:</a>".
           "<a name=\"%s\"></a>".
           "<td><b>%s</b></tr>\n",
           $t,$n+1,$s,$n+1,$qa,$q;
    printf "<tr valign=top><th>%s&nbsp;A%d:<td>\n%s</tr>\n",
           $s,$n+1,${A{$c}[$n]};
    print "</table>\n";
    print "[<a href=\"#top\">&uarr;&nbsp;Questions</a>]\n";
  }
}

print "<pre>\n";
print "\n" x 99;
print "</pre>\n";


sub sections {
  my $faq = shift;
  if ($faq eq 'all') {
    return @sections;
  } else {
    return ucfirst($faq);
  }
}

sub pre {
  local $_ = shift;
  s/<br>//g;
  s/\s+$//;
  return "<pre>$_</pre>\n";
}

sub anchor {
  local $_ = shift;
  s/<.+?>//g;
  s/\(.+?\)//g;
  s/\W/_/g;
  s/_+$//;
  return $_;
}

' ';
