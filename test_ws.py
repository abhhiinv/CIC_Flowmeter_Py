import time, threading, asyncio, websockets, json
from cicflowmeter.server import start_dashboard_server, broadcast_flow

start_dashboard_server(open_browser=False)
time.sleep(2)

async def test_ws():
    async with websockets.connect('ws://127.0.0.1:8000/ws') as ws:
        msg1 = await ws.recv()
        print('Init msg received')
        
        # Now trigger a broadcast from another thread
        def trigger():
            time.sleep(1)
            print('Triggering broadcast...')
            broadcast_flow({'test': 1, 'src_ip': '1.1.1.1', 'label': 'Normal Traffic'})
        
        threading.Thread(target=trigger).start()
        
        msg2 = await ws.recv()
        print('Flow msg received:', msg2[:100])

asyncio.run(test_ws())
