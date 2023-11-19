## Usage

```
# NTLM authentication
# Using password
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <PASSWORD> --authproto ntlm-password
# Using hex encoded password, useful if it contains annoying characters
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <HEX(PASSWORD)> --authproto ntlm-password --hex
# Same with base64
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <B64(PASSWORD)> --authproto ntlm-password --b64
# Using hash
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <NT_HASH> --authproto ntlm-nt

# Kerberos authentication
# Using password
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <PASSWORD> --authproto kerberos-password --dc dc.domain.local
# Using hash
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <NT_HASH> --authproto kerberos-rc4 --dc dc.domain.local
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <AES_HASH> --authproto kerberos-aes128 --dc dc.domain.local
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <AES_HASH> --authproto kerberos-aes256 --dc dc.domain.local
# Using ccache
ldapcheckr -d domain.local -u user -t 1.2.3.4 -s <CCACHE_FILEPATH> --authproto kerberos-ccache --dc dc.domain.local
```
