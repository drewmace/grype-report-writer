https://repo1.dso.mil/ironbank-tools/grype-parser
# Grype
```
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype dir:/tmp/iso-new/ -o json > /tmp/gdch_syscon.json
dnf install -y python3
pip3 install -r /tmp/requirements.txt
python3 /tmp/grype-parser.py --filename=/tmp/gdch_syscon.json --excel-report=/tmp/logs/grype_"$(date +%Y.%m.%d_%H.%M.%S)".xlsx
rm -rf /tmp/gdch_syscon.json
```