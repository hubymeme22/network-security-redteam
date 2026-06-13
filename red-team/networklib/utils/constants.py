"""
These methods/commands will be detected through sniffing method
we are only concerned with requests that may actually contain credentials
which is why the list below is very small
"""

HTTP_COMMANDS = (
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD"
)

# protocol command reference: https://ftpie.com/tools/ftp-command-reference
FTP_COMMANDS = (
    "USER",
    "PASS",
    "QUIT",
)

# protocol command reference: https://www.stevenrombauts.be/2018/12/test-smtp-with-telnet-or-openssl/
SMTP_COMMANDS = (
    "EHLO",
    "AUTH LOGIN",
    "AUTH PLAIN",
    "AUTH CRAM-MD5"
)
