import asyncio
import websockets
import json

async def listen_to_soc():
    uri = "ws://127.0.0.1:8000/ws/soc-dashboard"
    print(f"Connecting to SOC Dashboard at {uri}...")
    async with websockets.connect(uri) as websocket:
        print("✅ Connected! Waiting for CRITICAL threats...")
        try:
            while True:
                message = await websocket.recv()
                data = json.loads(message)
                print("\n" + "="*50)
                print("🚨 [LIVE SOC ALERT] 🚨")
                print(f"Severity : {data.get('severity')}")
                print(f"Module   : {data.get('module')}")
                print(f"Title    : {data.get('title')}")
                print(f"Case ID  : {data.get('case_id')}")
                print("="*50 + "\n")
        except websockets.exceptions.ConnectionClosed:
            print("Disconnected from SOC.")

if __name__ == "__main__":
    asyncio.run(listen_to_soc())
