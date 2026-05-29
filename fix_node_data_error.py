#!/usr/bin/env python3
"""
fix_node_data_error.py — Orange3 한글화 노드 채널 호환성 자동 수정 스크립트

배경:
  widgets_override/ 의 51개 위젯에서 Input/Output 채널 이름을 _tr.m[...] 으로
  한글 번역하면서, 채널의 내부 식별자(id)가 언어에 따라 변동되어
  영어/한글 모드 간 워크플로우(.ows) 로드 실패가 발생함.

해결책 (옵션 1):
  Input(_tr.m[N, "Data"], Table)
  → Input(_tr.m[N, "Data"], Table, id="Data")
  로 변환하여 GUI 표시명은 한글로 유지하되 내부 id는 영어로 고정.

사용법:
  # 1) 사전 검증 (변경 없음)
  python fix_node_data_error.py --dry-run

  # 2) 실제 변경 (백업 생성됨)
  python fix_node_data_error.py --apply

  # 3) 백업으로 복원
  python fix_node_data_error.py --revert
"""
import re
import sys
import glob
import shutil
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET_DIR = ROOT / "widgets_override"
BACKUP_SUFFIX = ".node_id_backup"

# ============ 변환 정규식 ============
# 패턴 A: Input/Output(_tr.m[N, "name"], Type [, ...])
#   캡처1: Input/Output 시작 ~ Type 끝
#   캡처2: 채널 이름 (id로 사용될 영어 원본)
#   캡처3: Type 다음의 구분자 (',' 또는 ')')
PATTERN_TR = re.compile(
    r'((?:Input|Output)\(_tr\.m\[\d+,\s*[\'"]([^\'"]+)[\'"]\],\s*[^,)]+)((?:,|\)))'
)

# 패턴 B: Output(ANNOTATED_DATA_SIGNAL_NAME, Type [, ...])
#   ANNOTATED_DATA_SIGNAL_NAME 상수도 한글 모드에서 "데이터"로 평가되어 id가 변동됨.
#   id="Data" 로 고정 (이 상수의 영어 원본은 항상 "Data").
PATTERN_ANNOT = re.compile(
    r'((?:Input|Output)\(ANNOTATED_DATA_SIGNAL_NAME,\s*[^,)]+)((?:,|\)))'
)
ANNOT_FIXED_ID = "Data"

# 호환성 유지를 위한 별칭 (기존 코드에서 PATTERN 참조 시)
PATTERN = PATTERN_TR


def collect_files() -> list[Path]:
    """변환 대상 파일 수집 (둘 중 하나라도 매칭되는 패턴 포함)."""
    loose = re.compile(r'(?:Input|Output)\((?:_tr\.m\[|ANNOTATED_DATA_SIGNAL_NAME)')
    files = []
    for f in glob.glob(str(TARGET_DIR / "**" / "*.py"), recursive=True):
        with open(f, encoding="utf-8") as fh:
            if loose.search(fh.read()):
                files.append(Path(f))
    return sorted(files)


def transform_line(line: str) -> tuple[str, bool]:
    """한 줄 변환. (변환된 줄, 변환되었는지 여부) 반환.
    이미 id= 가 있는 줄은 건너뜀."""
    if "id=" in line:
        return line, False
    # 패턴 A: _tr.m[N, "name"] → id="name" 추출
    if PATTERN_TR.search(line):
        new = PATTERN_TR.sub(
            lambda m: m.group(1) + f', id="{m.group(2)}"' + m.group(3),
            line,
        )
        return new, new != line
    # 패턴 B: ANNOTATED_DATA_SIGNAL_NAME → id="Data" 고정
    if PATTERN_ANNOT.search(line):
        new = PATTERN_ANNOT.sub(
            lambda m: m.group(1) + f', id="{ANNOT_FIXED_ID}"' + m.group(2),
            line,
        )
        return new, new != line
    return line, False


def line_matches_any_pattern(line: str) -> bool:
    return bool(PATTERN_TR.search(line) or PATTERN_ANNOT.search(line))


def process_file(path: Path, apply: bool) -> tuple[int, int]:
    """파일 처리. (변환 라인 수, 건너뛴 라인 수) 반환."""
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    n_change = 0
    n_skip = 0
    for line in lines:
        if line_matches_any_pattern(line):
            if "id=" in line:
                n_skip += 1
                new_lines.append(line)
            else:
                new_line, changed = transform_line(line)
                new_lines.append(new_line)
                if changed:
                    n_change += 1
        else:
            new_lines.append(line)

    if apply and n_change > 0:
        # 백업 생성 (이미 있으면 건드리지 않음 — 원본 보존)
        backup = path.with_suffix(path.suffix + BACKUP_SUFFIX)
        if not backup.exists():
            shutil.copy2(path, backup)
        # 변환 결과 저장
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

    return n_change, n_skip


def revert_all() -> int:
    """백업 파일로 복원. 복원된 파일 수 반환."""
    backups = list(TARGET_DIR.rglob(f"*{BACKUP_SUFFIX}"))
    n = 0
    for bk in backups:
        original = bk.with_suffix("")  # .node_id_backup 제거
        # .py.node_id_backup → .py 형태가 아닐 수 있어 정확한 처리
        original = Path(str(bk)[:-len(BACKUP_SUFFIX)])
        shutil.move(str(bk), str(original))
        n += 1
    return n


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true",
                   help="변경 없이 변환 대상만 출력")
    g.add_argument("--apply", action="store_true",
                   help="실제 변환 수행 (.node_id_backup 자동 생성)")
    g.add_argument("--revert", action="store_true",
                   help="백업 파일로 복원")
    args = parser.parse_args()

    if args.revert:
        n = revert_all()
        print(f"[OK] 복원 완료: {n}개 파일")
        return

    files = collect_files()
    print(f"=== 대상 파일 {len(files)}개 ===\n")

    total_change = 0
    total_skip = 0
    for path in files:
        n_change, n_skip = process_file(path, apply=args.apply)
        total_change += n_change
        total_skip += n_skip
        status = "[OK]" if args.apply and n_change > 0 else " "
        if n_change or n_skip:
            rel = path.relative_to(ROOT)
            print(f"  {status} {rel}: 변환 {n_change}, 건너뜀 {n_skip}")

    mode = "실제 적용" if args.apply else "DRY-RUN (변경 없음)"
    print(f"\n=== {mode} ===")
    print(f"  총 변환 라인 : {total_change}")
    print(f"  총 건너뛴 라인: {total_skip}")
    if args.apply:
        print(f"  백업 위치    : 각 파일 옆 *{BACKUP_SUFFIX}")
        print(f"  복원 명령    : python {Path(__file__).name} --revert")


if __name__ == "__main__":
    main()
