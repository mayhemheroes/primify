#! /usr/bin/python3
import atheris
import sys
import io
from PIL import Image, UnidentifiedImageError

with atheris.instrument_imports():
    from primify.base import PrimeImage



@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    byte_count = 4096
    image_length = 2 ** fdp.ConsumeIntInRange(1, 3)
    image_width = byte_count // image_length

    try:
        image = Image.frombytes("L", (image_length, image_width), fdp.ConsumeBytes(byte_count))
        resized_img = PrimeImage.resize_for_pixel_limit(image, fdp.ConsumeIntInRange(128, 4095))
        quant_img = PrimeImage.quantize_image(resized_img)
        PrimeImage.quantized_image_to_number(quant_img)
    except (UnidentifiedImageError, ValueError) as e:
        if isinstance(e, ValueError) and "magic number" not in str(e) and "tile cannot" not in str(e) and "not enough" not in str(e):
            raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
