import sys
from PIL import Image

def rgb565_to_rgb(pixel):
    """Convert 16-bit RGB565 value to 24bpp triplet.
    """
    r = pixel[0] & 0x1f
    g = (pixel[0] & 0xe0)>>5 | ((pixel[1] & 0x07)<<3)
    b = pixel[1]>>5
    return r,g,b


if __name__ == "__main__":
    if len(sys.argv) > 3:
        # Extract params
        path = sys.argv[1]
        width = int(sys.argv[2])
        outfile = sys.argv[3]

        # Process data
        with open(path, "rb") as glyph:
            # Read content
            content = glyph.read()

            # Create image
            height = len(content)//width
            img = Image.new("L", (width, height))
            print(img.size)

            
            nb_pixels = len(content)
            for i in range(nb_pixels):
                img.putpixel((i%width, i//width), content[i])
            
            # close image
            img.save(outfile)

