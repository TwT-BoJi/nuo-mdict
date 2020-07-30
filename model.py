from dataclasses import dataclass
from typing import Optional, List


@dataclass
class KeywordIndexMate:
    num_keyword: int
    len_comp: int
    len_unco: int
    head_keyword: bytes
    tail_keyword: bytes


@dataclass
class KeywordSectionMate:
    num_index: Optional[int] = None
    num_keyword: Optional[int] = None
    len_index_mate_unco: Optional[int] = None
    len_index_mate_comp: Optional[int] = None
    len_indexs: Optional[int] = None
    indexs_mate: Optional[List[KeywordIndexMate]] = None
