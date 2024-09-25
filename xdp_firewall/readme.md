The Light Firewall for CDN Node
---

This code use XDP for filtering

Also use BCC to access XDP.

Installation
----
install requirement module with PIP (Python 2.7 recommended)

in Ubuntu install :

```
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
sudo apt install python-pip
```


Running
------
For security use a Proxy(Nginx) to publish API and allow only specified host

API endpoint run on 127.0.0.0:5000 automatically

Change secret key in config.py file

create a linux daemon to run dxp.py



Usage
----
You can `POST` json data to API add ip blocks.
sample json format:
 
 ```POST http://IPADDRESS:PORT/add/ ```

```json
{
  "1.1.1.1": "1",
  "2.2.2.2": "2"
}

```
use `x_key_auth` in http header with secret key as a value.


Use `GET` to get list of blocked IP address.


also you can delete key.You must post 

 ```POST http://IPADDRESS:PORT/del/ ```

```json
{
  "1.1.1.1":  0,
  "2.2.2.2": 0
}

```

----



