import os
import PyPDF2
from docx import Document
from openpyxl import load_workbook
from pptx import Presentation
import pytesseract
from PIL import Image, ImageEnhance
import numpy as np
import cv2


def read_text(file_path: str) -> str:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(file_path, "rb") as f:
        return f.read().decode("utf-8", errors="replace")


def read_pdf(file_path: str) -> str:
    content = ""
    with open(file_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            try:
                text = page.extract_text()
                if text:
                    content += text + "\n"
            except Exception:
                continue
    return content


def read_docx(file_path: str) -> str:
    doc = Document(file_path)
    return "\n".join(p.text for p in doc.paragraphs)


def read_xlsx(file_path: str) -> str:
    wb = load_workbook(file_path, data_only=True)
    parts = []
    for sheet_name in wb.sheetnames:
        sheet = wb[sheet_name]
        for row in sheet.iter_rows():
            for cell in row:
                if cell.value is not None:
                    parts.append(str(cell.value))
    return "\n".join(parts)


def read_pptx(file_path: str) -> str:
    prs = Presentation(file_path)
    parts = []
    for slide in prs.slides:
        for shape in slide.shapes:
            if shape.has_text_frame:
                for paragraph in shape.text_frame.paragraphs:
                    text = paragraph.text.strip()
                    if text:
                        parts.append(text)
    return "\n".join(parts)


def _enhance_image(image: Image.Image) -> Image.Image:
    grayscale = image.convert("L")
    enhancer = ImageEnhance.Contrast(grayscale)
    contrasted = enhancer.enhance(2.0)
    thresholded = contrasted.point(lambda x: 0 if x < 100 else 255)
    arr = np.array(thresholded)
    denoised = cv2.fastNlMeansDenoising(arr, None, h=10,
                                         templateWindowSize=7,
                                         searchWindowSize=21)
    return Image.fromarray(denoised)


def read_image_ocr(file_path: str) -> str:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        image = Image.open(file_path)
        if image.mode in ("P", "PA"):
            image = image.convert("RGBA")
        if image.mode == "RGBA":
            bg = Image.new("RGB", image.size, (255, 255, 255))
            bg.paste(image, mask=image.split()[3])
            image = bg
        enhanced = _enhance_image(image)
        return pytesseract.image_to_string(enhanced)


EXTENSION_MAP = {
    ".txt": read_text, ".csv": read_text, ".log": read_text,
    ".json": read_text, ".xml": read_text, ".yml": read_text,
    ".yaml": read_text, ".ini": read_text, ".cfg": read_text,
    ".conf": read_text, ".md": read_text, ".html": read_text,
    ".htm": read_text, ".ps1": read_text, ".bat": read_text,
    ".cmd": read_text, ".py": read_text, ".js": read_text,
    ".ts": read_text,
    ".pdf": read_pdf,
    ".docx": read_docx,
    ".xlsx": read_xlsx,
    ".pptx": read_pptx,
    ".png": read_image_ocr, ".jpg": read_image_ocr,
    ".jpeg": read_image_ocr, ".gif": read_image_ocr,
    ".bmp": read_image_ocr,
}

SCANNABLE_EXTENSIONS = set(EXTENSION_MAP.keys())


def read_file(file_path: str) -> str:
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    reader = EXTENSION_MAP.get(ext, read_text)
    return reader(file_path)
