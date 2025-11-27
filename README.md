Windows 簡單啟動:

安裝必要模組:

pip install flask peewee flask_bcrypt

執行:

python app.py

連線:

http://localhost:5000

app.py 中若要綁定 IPv6:

app.run(host="your_ipv6_address", port=5000, debug=True)

