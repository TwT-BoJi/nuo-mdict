from dataclasses import dataclass, field
from typing import Optional, List, Any


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
    indexs_mate: List[KeywordIndexMate] = field(default_factory=list)
    keyword_index: Any = None


@dataclass
class RecordSectionMate:
    num_index: Optional[int] = None
    num_record: Optional[int] = None
    len_compunco: Optional[int] = None
    len_indexs: Optional[int] = None
    lens_index_comp: List[int] = field(default_factory=list)
    lens_index_unco: List[int] = field(default_factory=list)
    record_index: Optional[bytes] = None
