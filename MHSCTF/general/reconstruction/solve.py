from pwn import *
from PIL import Image, ImageOps
import numpy as np

def main():
    '''Create an image that contains the flag.'''
    with open('9712a0c4e51eae4c229538d050ae0d38.txt') as f:
        data = f.readline()

        rows = list(filter(None, data.split(';')))
        for i in range(0, len(rows)):
            # Remove all blanks.
            rows[i] = list(filter(None, rows[i].split(',')))

        height = len(rows)
        width = len(rows[0])

        log.info(f'Height: {height}, width: {width}.')

        na = np.array(rows, dtype=np.uint8)
        img = Image.fromarray(na)

        # Flip and rotate the image to actually make it legible.
        img = img.transpose(Image.FLIP_TOP_BOTTOM)
        img = img.transpose(Image.ROTATE_270)
        img.save('flag.png')


if __name__ == '__main__':
    main()