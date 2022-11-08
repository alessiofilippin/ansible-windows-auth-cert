# Ansible Windows Cert Based Auth

## Copyright

<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png" /></a><br />This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License</a>.

## Prerequisites

An SelfSigned Certificate:

```
## This is the public key generated from the Ansible server using:
cat > openssl.conf << EOL
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req_client]
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:[NAME_OF_THE_LOCAL_USER]@localhost
EOL
export OPENSSL_CONF=openssl.conf
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -out cert.pem -outform PEM -keyout cert_key.pem -subj "/CN=[NAME_OF_THE_LOCAL_USER]" -extensions v3_req_client
rm openssl.conf 
```

- Admin rights to execute the script.

- Setup Correct Access for RDP and SSH connections between Ansible Controller and Targets.

- If Targets are domain joined, make sure that certificate auth is enabled.

# How-To-Use
 
- Create Certificate.
- Create a windows cert folder on the Ansible Controller.
- Move cert.pem to the target VMs.
- Execute the Script on each target.
