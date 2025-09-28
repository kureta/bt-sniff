import asyncio
from time import sleep

from bleak import BleakClient

ADDRESS = "6D:F8:90:4D:C3:55"  # replace with your device’s BLE address


async def main():
    async with BleakClient(ADDRESS) as client:
        # discover all services & characteristics
        services = client.services
        for service in services:
            for char in service.characteristics:
                props = char.properties  # e.g. ['read','write','notify']
                # pick writable characteristics
                if "write" in props or "write_without_response" in props:
                    uuid = char.uuid
                    if uuid == "0000a031-5761-7665-7341-7564696f4c74":
                        continue
                    if uuid == "00002a00-0000-1000-8000-00805f9b34fb":
                        continue
                    wants_response = "write" in props
                    print(f"→ Writing 0x01 to {uuid}  props={props}")
                    try:
                        await client.write_gatt_char(
                            uuid, b"\x01", response=wants_response
                        )
                        print("   ✔ success")
                    except Exception as e:
                        print(f"   ✖ failed: {e}")
                    sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
