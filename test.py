from dataclasses import dataclass
from log import log


@dataclass
class Student:
    name: str


s = Student(name = 1)
log(f's: { s }')
log(f'c: { s.name }')