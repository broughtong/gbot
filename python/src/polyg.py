from polygon import RESTClient

client = RESTClient(api_key="pCMbVT7_sStLpU0cAbSj4E987FsSI2xI")

tickers = []
for t in client.list_tickers(
	market="crypto",
	active="true",
	order="asc",
	):
    tickers.append(t)

print(tickers)
