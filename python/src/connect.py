import websocket
import ssl
import json
import matplotlib.pyplot as plt

x = []
y = []

endpoint = 'wss://ws.kraken.com/v2'
params = {
    "method": "subscribe",
    "params": {
        "channel": "ticker",
        "symbol": [
            "BTC/USD"
        ]
    }
}

def on_open(ws):
    print('Opened Connection')
    ws.send(json.dumps(params))

def on_close(ws, a, b):
    print('Closed Connection')

def on_message(ws, message):
    global x, y
    if "heartbeat" in message:
        return
    js = json.loads(message)
    x.append(js["data"][0]["bid"])
    y.append(js["data"][0]["ask"])
    print(message)
    #print(js["data"][0]["bid"], js["data"][0]["ask"])

def on_error(ws, err):
  print("Got a an error: ", err)

ws = websocket.WebSocketApp(endpoint, on_open = on_open, on_close = on_close, on_message = on_message,on_error=on_error)
ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
