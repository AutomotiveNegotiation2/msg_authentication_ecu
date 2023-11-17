# Make Headerfile for Publickey
#!/bin/bash
python3 -c "import aursa_key_module as md; md.ExtractMyPubkey();"
