#! /usr/bin/python3
import atheris
import sys
import math
import logging

from PIL import Image, UnidentifiedImageError

# with atheris.instrument_imports():
from primify.base import PrimeImage

log_2 = math.log(2)

logging.disable(logging.CRITICAL)

@atheris.instrument_func
def TestOneInput(data):
    if len(data) < 7 or len(data) > 512:
        return -1

    fdp = atheris.FuzzedDataProvider(data)
    image_length = 2 ** fdp.ConsumeIntInRange(1, 3)
    byte_count = 2 ** math.floor(math.log(fdp.remaining_bytes()) / log_2)
    image_width = byte_count // image_length
    print(image_width, image_length)
    try:
        image = Image.frombytes("L", (image_length, image_width), fdp.ConsumeBytes(byte_count))
        resized_img = PrimeImage.resize_for_pixel_limit(image, byte_count - 1)
        quant_img = PrimeImage.quantize_image(resized_img)
        PrimeImage.quantized_image_to_number(quant_img)
    except (UnidentifiedImageError, ValueError) as e:
        if isinstance(e, ValueError) and "magic number" not in str(e) and "tile cannot" not in str(
                e) and "not enough" not in str(e):
            raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
