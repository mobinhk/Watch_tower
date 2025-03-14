# Welcome to kobi watchTower

# Installation
1. git clone the repo

2. install mongodb on linux server.

3. install shosubgo,subfinder,chaos,dnsx,httpx
```
go install github.com/incogbyte/shosubgo@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

pip3 install -r requirements.txt

```bash
python3 watchTower.py -h
``` 
# Provider supported
1. crt.sh
2. abuseipdb (replace with own session)
3. shodan    (replace with own shodan api key)
4. c99       (replace with own c99 api key)
5. subfinder
6. chaos


# Run

there is two modules for subdomain enumeration:
1. Run watchTower with single domain:
   ```bash
   python3 watchTower.py -u target.com --method all
   ```
   or with providers you want. for example:
   ```bash
   python3 watchTower.py -u target.com --method crt.sh,subfinder
   ```
2. you can run watchTower with multiple domain:
   you must add target to .yml file:
 ```
targets:
  - name: Epicgames
    domains:
      - epicgames.com
  - name: Amazon
    domains:amazon.com
```
  and run it (with yml file you can manage thread for faster enumeration ) : 
  ```bash
    python3 watchTower.py --target-file target.yml --method all --threads 1 
```

# Other commands
```
python3 watchTower.py --count-target target.com
python3 watchTower.py --count-dnsx  target.com
python3 watchTower.py --count-http-2xx target.com
python3 watchTower.py --count-http-3xx target.com
python3 watchTower.py --count-http-4xx target.com
python3 watchTower.py --count-http-5xx target.com
python3 watchTower.py --show-subdomains -u target.com

python3 watchTower.py --show-subdomains-dns -u target.com
python3 watchTower.py --show-http-2xx -u target.com
python3 watchTower.py --show-http-3xx -u target.com
python3 watchTower.py --show-http-4xx -u target.com
python3 watchTower.py --show-http-5xx -u target.com
python3 watchTower.py --db-drop -u target.com
```


![zomato](https://github.com/user-attachments/assets/40a6b790-0bf7-4f45-8d1a-93b6144751a8)

