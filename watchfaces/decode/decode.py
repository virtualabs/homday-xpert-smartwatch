"""
Smartwatch Watchface binary decoding
"""
import sys
import os.path
from struct import unpack, unpack_from
from PIL import Image

class WfHours:
    """Watchface Hours item
    """

    def __init__(self, container, header_offset):
        """Watchface hours item initialization
        """
        self.__container = container
        self.__offset = header_offset
        self.__data_offset = None
        self.__x = 0
        self.__y = 0
        self.__width = 0
        self.__height = 0
        self.__glyphs = []

    def __repr__(self) -> str:
        """Class representation.
        """
        return "<WfHours x=%d y=%d w=%d h=%d offset=%08x/>" % (
            self.__x, self.__y, self.__width, self.__height, self.__data_offset
        )

    def load(self):
        """Parse hours item
        """
        # Get item metadata
        _, self.__width, self.__height, _, _, self.__data_offset = unpack(
            "<BHHHHI", self.__container[self.__offset+1:self.__offset+14]
        )

        # Read item data located at offset
        print(f"data offset: {self.__data_offset:08x}")
        data_header = self.__container[self.__data_offset:self.__data_offset+12]
        assert data_header[:4] == b"\xff\xff\x04\x83"
        self.__x, self.__y = unpack_from("<HH", data_header, 4)

        # Load glyphs
        for i in range(10):
            glyph_offset, glyph_size = unpack(
                "<II",
                self.__container[self.__data_offset + 12 + i*8:self.__data_offset + 12 + (i+1)*8]
            )
            # Read glyph content
            self.__glyphs.append(
                self.__container[glyph_offset:glyph_offset+glyph_size]
            )
        
    def extract(self, outdir: str):
        """Extract data to output directory
        """
        # Save binary glyphs
        for i in range(10):
            # Save binary glyph
            glyph_path = os.path.join(outdir, f"glyph_{i}")
            with open(glyph_path+".bin", "wb") as glyph:
                glyph.write(self.__glyphs[i])
            
            # Convert glyph into greyscale png
            width = len(self.__glyphs[i])//self.__height
            glyph_img = Image.frombytes("L", (width, self.__height), self.__glyphs[i])
            glyph_img.save(glyph_path+".png")
               


class WatchFace:
    """WatchFace decoder/encoder
    """

    ITEM_HOURS = 0x03
    ITEM_MINUTES = 0x04

    def __init__(self, path: str):
        """Load a watchface
        """
        self.__path = path
        self.__raw = None
        self.__items = []

    def load(self):
        """Read watchface and decode content
        """
        try:
            with open(self.__path, "rb") as face:
                # Read content
                self.__raw = face.read()

                # Load sections
                self.load_items()
        except IOError:
            return False

    def load_hours(self, header):
        """Load 'hours' item from memory
        """
        # Get item metadata
        _, height, width, _, _, offset = unpack("<BHHHHI", header[1:])

        # Read item data located at offset
        data_header = self.__raw[offset:offset+12]
        assert data_header[:4] == b"\xff\xff\x04\x83"
        xcoord, ycoord = unpack("<II", data_header[4:8])
        print(f"Hours item ({xcoord}, {ycoord})")

        # Load glyphs in

    def load_items(self):
        """Read main header and load sections in memory
        """
        # Parse main header
        main_header = unpack("<HHHH", self.__raw[:8])
        
        # Consider the last 16-bit value as number of dir entries
        nb_items = main_header[3]

        for i in range(nb_items):
            # Read the item 14-byte header
            header = self.__raw[8 + i*14:8+(i+1)*14]

            # Get section type
            section_type = header[0]
            if section_type == WatchFace.ITEM_HOURS:
                item = WfHours(self.__raw, 8 + i*14)
                item.load()
                # temporary
                item.extract("/tmp/hours/")
                self.__items.append(item)

        print(self.__items)




def decode_watchface(path):
    """Decode watchface
    """
    with open(path, "rb") as face:
        content = face.read()

        # Parse main header
        main_header = unpack("<HHHH", content[:8])
        # Consider the last 16-bit value as number of dir entries
        nb_directory_entries = main_header[3]

        # Read dir entries
        for i in range(nb_directory_entries):
            a, b, c, d, e, offset = unpack("<HHHHHI", content[8 + i*14:8+(i+1)*14])
            print(f"= Section #{i}")
            print(f"|-> {a:04x}")
            print(f"|-> {b:04x}")
            print(f"|-> {c:04x}")
            print(f"|-> {d:04x}")
            print(f"|-> {e:04x}")
            print(f"|-> Content offset: {offset:08x}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        face = WatchFace(sys.argv[1])
        face.load()
    else:
        print(f"Usage: {sys.argv[0]} [filename]")
