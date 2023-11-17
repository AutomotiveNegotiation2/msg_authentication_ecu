# Make Header file for privatekey 
#!/bin/bash
python3 -c "import aursa_key_module as md; md.ExtractMyPrvkey();"
