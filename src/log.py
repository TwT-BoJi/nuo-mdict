import sys
from datetime import datetime


def log(x):
    v = sys.version_info
    version = f'{v.major}.{v.minor}.{v.micro}'
    time = f'{datetime.now():%Y/%m/%d %H:%M:%S.%f}'
    print(f'>>>> {time} | python: {version}')
    print(f'{x}')
    print()
