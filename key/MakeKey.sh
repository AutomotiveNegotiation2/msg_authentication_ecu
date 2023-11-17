# Make RSA2048 key pair
#!/bin/bash
python3 -c "import aursa_key_module as md; md.GenKey();"
