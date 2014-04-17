heartbleed
==========

PoC perl script

Syntax:
  heartbleed.pl -h hostname [-p port] [ -o protocol] [-d]

Options:

  -h \< FQDN or IP address \> (required)
  
  -p \< port number \> (optional, but defaults to 443)
  
  -o \< ftp | smtp | imap | pop3 | xmpp \> (optional)
  
  -d \< debug level \> (optional)
  

example:
  -h www.example.com -p 443
