import asyncio
import os
import aiofiles

# Define the InvalidMacError exception
class InvalidMacError(Exception):
    pass

# Define the VendorNotFoundError exception
class VendorNotFoundError(Exception):
    def __init__(self, mac):
        self.mac = mac

    def __str__(self):
        return f"The vendor for MAC {self.mac} could not be found."

class MacLookup:
    def __init__(self):
        self.vendors = None

    async def load_vendors(self):
        if self.vendors is None:
            vendors = {}
            async with aiofiles.open(self.get_oui_file_path(), mode='r') as f:
                async for line in f:
                    if "(base 16)" in line:
                        prefix = line.split("(base 16)")[0].strip()
                        vendor = line.split("(base 16)")[1].strip()
                        vendors[prefix] = vendor
            self.vendors = vendors

    def get_oui_file_path(self):
        parent_dir = os.path.dirname(os.path.dirname(__file__))
        return os.path.join(parent_dir, 'resources', 'oui.txt')

    def sanitise(self, mac):
        mac = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        try:
            int(mac, 16)
        except ValueError:
            raise InvalidMacError(f"{mac} contains unexpected character")
        if len(mac) > 12:
            raise InvalidMacError(f"{mac} is not a valid MAC address (too long)")
        return mac

    async def get_vendor(self, mac):
        """
        Asynchronously get the vendor for a given MAC address.

        Args:
            mac (str): The MAC address.

        Returns:
            str: The vendor for the MAC address.

        Raises:
            InvalidMacError: If the MAC address is invalid.
            VendorNotFoundError: If the vendor for the MAC address is not found.
        """
        await self.load_vendors()
        # Sanitize the MAC address
        sanitized_mac = self.sanitise(mac)

        # Check if the MAC address prefix is in the vendors dictionary
        for prefix in self.vendors:
            if sanitized_mac.startswith(prefix):
                # Return the vendor
                return self.vendors[prefix]
        else:
            # Raise a VendorNotFoundError if the vendor is not found
            raise VendorNotFoundError(f"Vendor not found for MAC address {mac}")

   
# Usage
# async def main():
#     mac_lookup = MacLookup()
#     try:
#         vendor = await mac_lookup.get_vendor("00:11:22:33:44:55")
#         print(vendor)
#     except (InvalidMacError, VendorNotFoundError) as e:
#         print(e)

# asyncio.run(main())