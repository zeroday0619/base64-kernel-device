# base64 encode/decode device

## Install
```bash
sudo dkms add .
sudo sudo dkms build base64dev/0.1 
sudo dkms install base64dev/0.1
sudo modprobe base64dev
```

## Usage
```bash
echo -n "Hi, I am Linux Developer" > /dev/base64enc
cat /dev/base64enc

echo -n "SGksIEkgYW0gTGludXggRGV2ZWxvcGVy" > /dev/base64dec
cat /dev/base64dec
```
