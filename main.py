from datetime import datetime


def log(x):
    time = datetime.now()
    print(f'#### {time:%Y-%m-%d %H:%M:%S.%f}')
    print(f'>>>> {x}')
    print()


def main():
    with open('./mdict/coca.mdx', 'rb') as file:
        log(file)


main()