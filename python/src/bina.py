import asyncio
from binance import AsyncClient, BinanceSocketManager

# API keys
API_KEY = '<api_key>'
API_SECRET = '<api_secret>'

# Binance API endpoint
BASE_URL = 'https://fapi.binance.com'

async def main():
    client = await AsyncClient.create(api_key=API_KEY,api_secret=API_SECRET)
    bm = BinanceSocketManager(client)
    # start any sockets here, i.e a trade socket
    ts = bm.futures_socket() # Tried also bm.futures_user_socket()
    # then start receiving messages
    async with ts as tscm:
        while True:
            res = await tscm.recv()
            print(res)

    await client.close_connection()


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
