import sys
import random
from time import sleep
from rich.text import Text
from rich.console import Console
from string import ascii_letters, digits
from rich.live import Live
from rich.table import Table
# Code by @s1kr10s

def get_chars(i: int) -> str:
    chars = random.sample(ascii_letters + digits, k=i)
    return " ".join(chars).upper()

def shuffle(line: str, name_length: int):
    for _ in range(0, random.randint(4, 8)):
        print(f"\t{get_chars(name_length)}", end="\r")
        sleep(0.10)
    print(f"\t{line}")

def print_banner(name="-FIND WIN API-", author="by s1kr10s"):
    name_length = len(name) + 4
    name = " ".join(name.upper())
    name = f"{get_chars(2)} {name} {get_chars(2)}"
    print("\n")

    lines = [get_chars(name_length), name, get_chars(name_length)]
    for line in lines:
        shuffle(line, name_length)
    print(f"                    {author}\n")

def parse_ida_exports(filetoparse):
    valuenum = ''.join(random.sample('0123456789abcdefghi', 5))
    with open(filetoparse, "r") as f:
        for line in f:
            columns = line.strip().split("\t")
            functions = columns[2]
            file = open(f'file_{valuenum}.txt', 'a')
            file.write(f'{functions}\n')
            file.close()

    return valuenum

def main(fileoutput):
    print_banner()

    table = Table()
    table.add_column("Function Name", style="purple on black")
    #table.add_column("Description", style="green")
    table.add_column("Library", style="yellow on black")
    table.add_column("Associated Attacks", style="red on black")
    table.add_column("Documentation", style="blue on black")
    console = Console()

    name_winapi = []
    list_api_to_compare = []
    coincidences = []

    # se listan las winapi
    with open("apis.list", "r") as file_winapi:
        arr_winapi = file_winapi.readlines()

        for list_winapi in arr_winapi:
            winapi = list_winapi.strip()
            split_winapi = winapi.split('|')
            name_winapi.append((split_winapi[0],split_winapi[1],split_winapi[2],split_winapi[3],split_winapi[4]))

    # se leer el archivo con la lista de api a identificar
    with open(f"{fileoutput}", "r") as file_listapi:
        arr_listapi = file_listapi.readlines()

        for list_api in arr_listapi:
            api = list_api.strip()
            list_api_to_compare.append(api)

    for value in list_api_to_compare:
        for name in name_winapi:
            if value == name[0]:
                # https://malapi.io/winapi/{name[0]}
                table.add_row(f"{name[0]}", f"{name[2]}", f"{name[3]}", f"{name[4]}")

    console.print(table)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f'Use: python3 {sys.argv[0]} listapi.txt')
        sys.exit()

    valuenum = parse_ida_exports(sys.argv[1])    
    main(f'file_{valuenum}.txt')