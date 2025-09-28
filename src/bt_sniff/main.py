# pyright: basic

import asyncio

import typer
from dbus_next.aio.message_bus import MessageBus
from dbus_next.constants import BusType
from typing_extensions import Annotated

from bt_sniff.tracker import Window

# bluetooth namespace in dbus
BUS_NAME = "org.bluez"
# this machines bluetooth adapter
ADAPTER = "hci0"


def get_device_path(addr):
    return f"/org/bluez/{ADAPTER}/dev_" + addr.replace(":", "_")


def get_char_path(address, service, handle):
    return f"/org/bluez/{ADAPTER}/dev_{address.replace(':', '_')}/service{service:04x}/char{handle:04x}"


def make_handler(path):
    def on_properties_changed(interface, changed, invalidated):
        if interface != "org.bluez.GattCharacteristic1":
            return
        if invalidated:
            print(f"invalidated: {invalidated}")
        if "Value" in changed:
            data = bytes(changed["Value"].value)
            print(f"{path} → {data.hex()}")

    return on_properties_changed


async def _listen_all_notifications(address):
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    # get all managed objects once
    intro = await bus.introspect(BUS_NAME, "/")
    obj_mgr = bus.get_proxy_object(BUS_NAME, "/", intro).get_interface(
        "org.freedesktop.DBus.ObjectManager"
    )
    objs = await obj_mgr.call_get_managed_objects()

    notify_chars = []
    # find characteristics with "notify" in Flags
    for path, ifaces in objs.items():
        gatt = ifaces.get("org.bluez.GattCharacteristic1")
        if not gatt:
            continue
        if not path.startswith(get_device_path(address)):
            continue
        flags = gatt["Flags"].value  # e.g. ['read','write','notify']
        if "notify" in flags:
            notify_chars.append(path)

    if not notify_chars:
        raise RuntimeError("No notifiable characteristics found")

    # subscribe to each and watch for Value changes
    for char_path in notify_chars:
        intro = await bus.introspect(BUS_NAME, char_path)
        proxy = bus.get_proxy_object(BUS_NAME, char_path, intro)
        char_if = proxy.get_interface("org.bluez.GattCharacteristic1")
        props_if = proxy.get_interface("org.freedesktop.DBus.Properties")

        props_if.on_properties_changed(make_handler(char_path))
        await char_if.call_start_notify()
        print("Started notify on", char_path)

    # hang forever
    await asyncio.get_event_loop().create_future()


async def _listen_service_char(address, service, char):
    # Connect to dbus
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    # Get all managed objects
    introspection = await bus.introspect(BUS_NAME, "/")
    object_manager = bus.get_proxy_object(BUS_NAME, "/", introspection).get_interface(
        "org.freedesktop.DBus.ObjectManager"
    )
    objects = await object_manager.call_get_managed_objects()

    char_path = get_char_path(address, service, char)
    introspection = await bus.introspect(BUS_NAME, char_path)
    proxy = bus.get_proxy_object(BUS_NAME, char_path, introspection)
    characteristic_interface = proxy.get_interface("org.bluez.GattCharacteristic1")
    properties_interface = proxy.get_interface("org.freedesktop.DBus.Properties")

    properties_interface.on_properties_changed(make_handler(char_path))
    await characteristic_interface.call_start_notify()
    print("Started notify on", char_path)

    # hang forever
    await asyncio.get_event_loop().create_future()


app = typer.Typer(
    help="For sniffing incoming bluetooth messages.", no_args_is_help=True
)


@app.command()
def listen_all(
    address: Annotated[str, typer.Argument(help="Address of the bluetooth device")],
):
    """
    Listen to all incoming messages from a given device.
    """
    asyncio.run(_listen_all_notifications(address))


@app.command()
def listen(
    address: Annotated[str, typer.Argument(help="Address of the bluetooth device")],
    service: Annotated[
        int,
        typer.Argument(
            help="Service number as hex (like 0xAA)", parser=lambda x: int(x, 0)
        ),
    ],
    handle: Annotated[
        int,
        typer.Argument(help="Handle as hex (like 0xAA)", parser=lambda x: int(x, 0)),
    ],
):
    """
    Listen to a specific service and handler on a device.
    """
    asyncio.run(_listen_service_char(address, service, handle))


@app.command()
def tracker(
    address: Annotated[
        str, typer.Argument(help="Address of the bluetooth device")
    ] = "",
):
    """
    Stream tracker data os osc messages.
    """
    Window(address).mainloop()
