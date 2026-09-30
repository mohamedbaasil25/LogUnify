"""Tiny dependency-free PDF writer (text only: A4, Helvetica, wrapped lines, page numbers, coloured labels).

Good enough for an auditor report, and it avoids a heavy dependency in a security tool. It is not a layout engine:
line breaks use an average glyph width, and text outside Latin-1 is replaced with '?'.
"""
import re

W, H, MARGIN = 595, 842, 50
_LEADING = 1.3


def _latin(s: str) -> str:
    s = s.replace("–", "-").replace("—", "-").replace("’", "'").replace("‘", "'")
    return s.encode("latin-1", "replace").decode("latin-1")


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class Pdf:
    def __init__(self, title: str, footer: str = ""):
        self.title, self.footer = _latin(title), _latin(footer)
        self.pages: list[list[str]] = [[]]
        self.y = H - MARGIN

    def _new_page(self):
        self.pages.append([])
        self.y = H - MARGIN

    def space(self, pts: float = 6):
        self.y -= pts

    def text(self, s: str, size: float = 10, bold: bool = False, color=(0, 0, 0), indent: float = 0, gap: float = 0):
        s = _latin(str(s))
        cw = size * (0.56 if bold else 0.52)
        width = max(10, int((W - 2 * MARGIN - indent) / cw))
        lines: list[str] = []
        for para in s.split("\n"):
            lines += _wrap(para, width) or [""]
        font = "F2" if bold else "F1"
        for ln in lines:
            if self.y - size < MARGIN + 20:
                self._new_page()
            r, g, b = color
            self.pages[-1].append(f"BT /{font} {size} Tf {r} {g} {b} rg {MARGIN + indent:.1f} {self.y - size:.1f} Td ({_esc(ln)}) Tj ET")
            self.y -= size * _LEADING
        self.y -= gap

    def rule(self):
        if self.y < MARGIN + 30:
            self._new_page()
        self.pages[-1].append(f"0.7 0.7 0.7 RG 0.5 w {MARGIN} {self.y:.1f} m {W - MARGIN} {self.y:.1f} l S")
        self.y -= 6

    def render(self) -> bytes:
        objs: list[bytes] = []                    # index i -> object number i+1
        n_pages = len(self.pages)
        first_page_obj = 5                        # 1 catalog, 2 pages, 3 F1, 4 F2, then (page, content) pairs
        kids = " ".join(f"{first_page_obj + 2 * i} 0 R" for i in range(n_pages))
        objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objs.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode())
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        for i, page in enumerate(self.pages):
            foot = f"BT /F1 8 Tf 0.4 0.4 0.4 rg {MARGIN} 30 Td ({_esc(self.footer)}   |   page {i + 1} of {n_pages}) Tj ET"
            stream = "\n".join(page + [foot]).encode("latin-1")
            c = first_page_obj + 2 * i + 1
            objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                        f"/Contents {c} 0 R >>".encode())
            objs.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
        out = bytearray(b"%PDF-1.4\n")
        offsets = []
        for i, o in enumerate(objs, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").encode()
        return bytes(out)


def _wrap(s: str, width: int) -> list[str]:
    out, cur = [], ""
    for word in re.split(r"(\s+)", s):
        if len(word) > width:                     # unbreakable token (hash, URL): hard-split it
            if cur.strip():
                out.append(cur.rstrip())
                cur = ""
            out += [word[i:i + width] for i in range(0, len(word), width)]
            continue
        if len(cur) + len(word) > width:
            out.append(cur.rstrip())
            cur = word.lstrip()
        else:
            cur += word
    if cur.strip():
        out.append(cur.rstrip())
    return out
